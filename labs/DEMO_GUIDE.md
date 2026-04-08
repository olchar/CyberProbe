# CyberProbe Quick Demo Guide

**🎯 Purpose**: This guide helps you demonstrate CyberProbe's capabilities in 15-30 minutes, whether you're showing it to management, fellow analysts, or during training sessions.

**👥 Target Audience**: 
- Security Operations Center (SOC) analysts (beginner to advanced)
- Security managers evaluating investigation tools
- IT professionals learning threat hunting
- Anyone wanting a quick hands-on tour

---

## Table of Contents

1. [What is CyberProbe?](#what-is-cyberprobe)
2. [5-Minute Quick Demo](#5-minute-quick-demo)
3. [15-Minute Comprehensive Demo](#15-minute-comprehensive-demo)
4. [30-Minute Deep Dive Demo](#30-minute-deep-dive-demo)
5. [Demo Scenarios by Skill Level](#demo-scenarios-by-skill-level)
6. [Queries You Can Run](#queries-you-can-run)
7. [Skills You Can Demonstrate](#skills-you-can-demonstrate)
8. [Common Demo Pitfalls](#common-demo-pitfalls)
9. [Demo Setup Checklist](#demo-setup-checklist)

---

## What is CyberProbe?

**In Simple Terms**: CyberProbe is an investigation toolkit that helps security analysts investigate suspicious activity in Microsoft 365 and Azure environments. Think of it as a "detective's toolkit" for cybersecurity.

**What It Does**:
- 🔍 Investigates suspicious user behavior (unusual logins, impossible travel, etc.)
- 🌐 Analyzes IP addresses to determine if they're malicious
- 📊 Creates professional investigation reports automatically
- 🤖 Uses AI (GitHub Copilot) to automate repetitive tasks
- 📈 Generates executive dashboards for leadership

**Key Components**:

| Component | What It Does | For Beginners | For Experts |
|-----------|--------------|---------------|-------------|
| **KQL Queries** | Search security logs for suspicious activity | Think: Google search for security events | Advanced threat hunting with custom detection logic |
| **MCP Tools** | Automate data collection from Microsoft systems | Think: Autopilot for investigations | Programmatic API access for custom integrations |
| **IP Enrichment** | Check if IP addresses are malicious | Think: "Is this caller safe?" lookup | Multi-source threat intelligence correlation |
| **Agent Skills** | Teach AI how to investigate for you | Think: Training an assistant | Custom automation workflows with Copilot |
| **Reports** | Professional summaries of findings | Think: Automated PowerPoint for executives | Standardized incident documentation |

---

## 5-Minute Quick Demo

**Goal**: Show the fastest path from "suspicious activity" to "professional report"

**Scenario**: "A user's account may be compromised - let's investigate!"

### Step 1: Use AI to Investigate (2 minutes)

**What to say**: 
> "Instead of manually running dozens of queries, I'll just ask GitHub Copilot to investigate this user for me."

**What to do**:
1. Open VS Code with CyberProbe workspace
2. Open GitHub Copilot Chat (`Ctrl+Shift+I`)
3. Type exactly:
   ```
   Investigate user03@contoso.com for the last 7 days
   ```

**Real Example**: See [investigation_user03_2026-01-20.html](../reports/investigation_user03_2026-01-20.html) for actual output

**What happens** (automatically):
- ✅ Extracts user details from Microsoft Graph
- ✅ Queries sign-in logs for unusual locations
- ✅ Checks for impossible travel alerts
- ✅ Identifies suspicious IP addresses
- ✅ Enriches IPs with threat intelligence
- ✅ Creates investigation report with all findings

**Expected time**: ~60-90 seconds

### Step 2: Review the Report (2 minutes)

**What to say**:
> "Here's the automatically generated report. Let me show you the key findings."

**What to show**:
1. Open the HTML report that was generated: `reports/investigation_user03_2026-01-20.html`
2. Point out these sections:
   - **User Profile**: Basic info (name, department, roles - user03 has 21 group memberships!)
   - **Authentication Analysis**: 51 sign-ins, 33.3% failure rate, VPN detected
   - **IP Address Analysis**: Geographic locations and threat scores (20.97.10.99 flagged as VPN)
   - **Privilege Escalation**: 3 access package requests with minimal justification
   - **Risk Assessment**: Overall risk level HIGH with 7 risk factors identified
   - **Recommended Actions**: 16+ actionable recommendations organized by priority

**Key talking points**:
- "Notice how it automatically checked 7 days of sign-in history"
- "The IP addresses were checked against 3 threat intelligence sources"
- "If there were critical findings, they'd be highlighted in red"

### Step 3: Show Executive Summary (1 minute)

**What to say**:
> "We can also export this data for leadership dashboards."

**What to do**:
1. Open PowerShell terminal
2. Generate an HTML report:
   - Ask Copilot: `Generate a report for this investigation`
3. Show the generated HTML report with incident summary data

**Demo complete!** ✅

---

## 15-Minute Comprehensive Demo

**Goal**: Show investigation workflow + manual analysis capabilities

**Scenario**: "We detected a phishing email - let's trace what happened after the user clicked the link"

### Part 1: Sample Data Overview (3 minutes)

**What to say**:
> "Let me show you the realistic sample data included for training and testing."

**What to do**:
1. Navigate to `labs/sample-data/`
2. Open `incidents/phishing_incident_sample.json`
3. Explain the structure:
   ```json
   {
     "incident_id": "INC12345",
     "title": "Phishing Email - Credential Harvesting Campaign",
     "severity": "High",
     "iocs": {
       "ips": ["185.220.101.45", "45.142.120.1"],
       "urls": ["http://malicious-site.com/login"]
     }
   }
   ```

**Key points**:
- "This is what a real incident looks like in JSON format"
- "We can use this to practice investigations without live data"
- "The sample includes malicious IPs we can enrich"

### Part 2: Manual IP Enrichment (4 minutes)

**What to say**:
> "Let's check if these IP addresses are actually malicious using threat intelligence."

**What to do**:
1. Open PowerShell terminal
2. Run the enrichment script:
   ```powershell
   cd enrichment
   python enrich_ips.py 185.220.101.45 45.142.120.1
   ```
3. Wait for results (~10-15 seconds)
4. Show the output:
   ```
   IP: 185.220.101.45
   ├─ Location: Russia
   ├─ Abuse Score: 72%
   ├─ VPN/Tor: Yes
   └─ Risk Level: CRITICAL
   ```

**Key talking points**:
- "Abuse score above 50% means confirmed malicious"
- "VPN/Tor detection indicates attempts to hide identity"
- "This data comes from AbuseIPDB, IPInfo, and VPNapi"
- "All results saved to `enrichment/ip_enrichment_results.json`"

### Part 3: Run a KQL Query (5 minutes)

**What to say**:
> "Now let's manually query our security logs to see if anyone else was targeted."

**What to do**:
1. Open `Investigation-Guide.md` Section 8 (KQL queries)
2. Show Query 11 (Threat Intelligence IP Enrichment)
3. Copy the query and explain each part:
   ```kql
   let target_ips = dynamic(["185.220.101.45", "45.142.120.1"]);
   
   ThreatIntelIndicators
   | where NetworkSourceIP in (target_ips)
   | where IsActive and (ValidUntil > now() or isempty(ValidUntil))
   | project IPAddress, ThreatDescription, Confidence
   ```

**Break it down** (beginner-friendly):
- `let target_ips = ...` → "These are the IPs we want to check"
- `ThreatIntelIndicators` → "This is Microsoft's threat database"
- `where NetworkSourceIP in (target_ips)` → "Find matching IPs"
- `project` → "Show only these columns in results"

**Show the execution**:
4. If you have MCP access, run via Copilot:
   ```
   Run this KQL query on Sentinel to check these IPs: 185.220.101.45, 45.142.120.1
   ```
5. OR demonstrate using Azure Portal → Sentinel → Logs

**Expected results**:
- Show if the IPs are in Microsoft's threat database
- Explain confidence scores (0-100 scale)
- Point out threat descriptions (e.g., "C2 server", "Phishing infrastructure")

### Part 4: Use an Agent Skill (3 minutes)

**What to say**:
> "CyberProbe includes 'Agent Skills' - pre-built workflows that teach AI assistants how to investigate."

**What to do**:
1. Open `.github/skills/threat-enrichment/SKILL.md`
2. Show the skill structure:
   ```yaml
   ---
   name: threat-enrichment
   description: Multi-source threat intelligence enrichment for IPs
   ---
   ```
3. Explain how it works:
   - "This skill tells GitHub Copilot HOW to enrich IPs"
   - "When you ask about an IP, Copilot reads this skill"
   - "It automatically runs the enrichment script"
   - "No need to remember commands or syntax"

**Demonstrate**:
4. In Copilot Chat, type:
   ```
   Is 185.220.101.45 malicious?
   ```
5. Watch as Copilot:
   - Activates the `threat-enrichment` skill
   - Runs `enrich_ips.py 185.220.101.45`
   - Returns formatted analysis

**Key point**:
> "This is how we make investigations accessible to junior analysts - they just ask questions in plain English!"

---

## 30-Minute Deep Dive Demo

**Goal**: Show complete investigation workflow from detection to remediation

**Scenario**: "Impossible travel alert triggered - user signed in from Seattle, then Nigeria 30 minutes later"

### Part 1: Discovery with MCP Tools (8 minutes)

**What to say**:
> "Let's use the Model Context Protocol (MCP) to automatically pull data from Defender XDR."

**Background (simple explanation)**:
- "MCP = a way for AI to talk to Microsoft's security systems"
- "Instead of clicking through 10 different portals, we query everything in code"
- "Think of it like API access, but easier"

**What to do**:

**1.1 List Recent High-Severity Incidents**
```
Hey Copilot, show me the most severe incidents from Defender XDR today
```

**Behind the scenes** (explain if asked):
- Copilot calls `mcp_triage_ListIncidents`
- Filters by: `severity: High`, `createdAfter: today`
- Returns JSON with incident details

**1.2 Get Specific Incident Details**
```
Get full details for incident #41456 including all alerts
```

**What Copilot does**:
- Calls `mcp_triage_GetIncidentById(incidentId: "41456")`
- Retrieves:
  - All alerts in the incident
  - User evidence (who was affected)
  - IP evidence (where they signed in from)
  - Cloud app evidence (what apps were accessed)

**Show the output structure**:
```json
{
  "incidentId": "41456",
  "title": "Suspicious sign-in from Nigeria",
  "severity": "High",
  "evidence": [
    {
      "type": "userEvidence",
      "userPrincipalName": "user@contoso.com",
      "roles": ["compromised"]
    },
    {
      "type": "ipEvidence",
      "ipAddress": "102.89.23.45",
      "location": "Lagos, NG"
    }
  ]
}
```

### Part 2: SessionId Forensic Tracing (10 minutes)

**What to say**:
> "Now the critical part - we need to figure out if this Nigerian sign-in was legitimate or an attacker."

**Explain the concept** (beginner-friendly):
- "Every time you log in, Microsoft creates a 'session ID'"
- "All your activity in that session shares the same ID"
- "If we trace the session ID backwards, we can find where it started"
- "If it started in Seattle (user's normal location), it's likely legitimate travel"
- "If it started in Nigeria, that's the compromise point"

**What to do**:

**2.1 Extract SessionId from the Nigerian Sign-In**

Show the query from `Investigation-Guide.md` Section 9:
```kql
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName =~ 'user@contoso.com'
| where IPAddress == '102.89.23.45'  // The Nigerian IP
| where isnotempty(SessionId)
| distinct SessionId
| take 1
```

**Explain line by line**:
- `union isfuzzy=true` → "Search both interactive AND non-interactive sign-ins"
- `where TimeGenerated > ago(24h)` → "Last 24 hours only"
- `where IPAddress == '102.89.23.45'` → "Just the suspicious Nigerian IP"
- `where isnotempty(SessionId)` → "Only rows that have a session ID"
- `distinct SessionId` → "Give me unique session IDs"

**Expected output**:
```
SessionId: abc123-def456-789ghi
```

**2.2 Trace the Complete Session Chain**

```kql
let session_id = 'abc123-def456-789ghi';
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where SessionId == session_id
| project TimeGenerated, IPAddress, Location, AppDisplayName, AuthenticationRequirement
| order by TimeGenerated asc
```

**Expected results** (show on screen):
```
Time                  | IP Address      | Location        | App                | Auth Type
--------------------- | --------------- | --------------- | ------------------ | ----------------
2026-01-16 08:00:00   | 198.51.100.50   | Seattle, US     | Office 365         | MFA
2026-01-16 08:05:00   | 198.51.100.50   | Seattle, US     | OneDrive           | Single Factor
2026-01-16 08:30:00   | 102.89.23.45    | Lagos, NG       | Outlook            | Single Factor
2026-01-16 08:35:00   | 102.89.23.45    | Lagos, NG       | SharePoint         | Single Factor
```

**Analysis** (walk through the findings):
1. **FIRST entry (08:00)**: 
   - Location: Seattle (user's home location)
   - IP: 198.51.100.50 (corporate VPN)
   - Auth Type: MFA (user physically verified their identity)
   - **Conclusion**: "This is the legitimate user logging in"

2. **Subsequent entries (08:05)**:
   - Same Seattle IP
   - Auth Type: Single Factor (token refresh, not new login)
   - **Conclusion**: "User browsing normally from Seattle"

3. **Nigerian entries (08:30, 08:35)**:
   - Different IP (Lagos)
   - Same session ID (key!)
   - Auth Type: Single Factor (still using the same token from Seattle login)
   - **Conclusion**: "This is likely the user traveling and continuing to use their already-authenticated session"

**Verdict**:
> "Since the initial MFA authentication happened in Seattle (user's normal location), this appears to be legitimate business travel to Nigeria. The session tokens are still valid, so the user didn't need to re-authenticate."

**Alternative scenario** (show what compromise looks like):
```
Time                  | IP Address      | Location        | Auth Type
--------------------- | --------------- | --------------- | ----------------
2026-01-16 08:00:00   | 102.89.23.45    | Lagos, NG       | MFA ⚠️
2026-01-16 08:05:00   | 102.89.23.45    | Lagos, NG       | Single Factor
```
> "If the FIRST MFA happened in Nigeria, that's definite compromise - force password reset immediately!"

### Part 3: IP Enrichment Deep Dive (7 minutes)

**What to say**:
> "Even though we think it's legitimate, let's verify the Nigerian IP isn't on any blacklists."

**What to do**:

**3.1 Run Multi-Source Enrichment**
```powershell
python enrichment/enrich_ips.py 102.89.23.45
```

**While it runs** (~15 seconds), explain the data sources:
- **AbuseIPDB**: "Crowdsourced abuse reports from 100,000+ users"
  - Scores 0-100% (confidence that IP is malicious)
  - Abuse score > 50% = confirmed malicious
  
- **IPInfo**: "Geographic and network data"
  - Shows: City, region, country, postal code
  - ISP/organization (who owns the IP)
  - ASN (Autonomous System Number - like a "neighborhood ID" for IPs)
  
- **VPNapi**: "Detects anonymization services"
  - Checks if IP is: VPN, Proxy, Tor exit node
  - Legitimate users rarely use Tor; attackers often do

**3.2 Interpret Results**

Show the enrichment output:
```json
{
  "ip": "102.89.23.45",
  "city": "Lagos",
  "region": "Lagos",
  "country": "NG",
  "org": "AS37282 MainOne Cable Company",
  
  "abuseipdb": {
    "abuse_confidence_score": 12,
    "total_reports": 3,
    "is_whitelisted": false
  },
  
  "vpnapi": {
    "is_vpn": false,
    "is_proxy": false,
    "is_tor": false
  },
  
  "risk_assessment": {
    "risk_score": 15,
    "risk_level": "LOW",
    "risk_factors": [
      "AbuseIPDB: 12% confidence (clean)",
      "No VPN/Proxy/Tor detected",
      "Minimal abuse reports (3 total)"
    ]
  }
}
```

**Explain the verdict** (beginner-friendly):
- **Abuse score 12%**: "Only 12% confidence it's malicious - very low"
- **3 total reports**: "Out of millions of IPs, only 3 complaints - normal background noise"
- **No VPN/Tor**: "Direct internet connection, not hiding their identity"
- **MainOne Cable**: "Legitimate Nigerian ISP, not a data center or hosting provider"
- **Risk Level: LOW**: "Overall safe - consistent with legitimate business travel"

**Contrast with malicious example** (show a reference):
```json
{
  "ip": "185.220.101.45",
  "abuse_confidence_score": 100,  // ⚠️ Maximum risk
  "total_reports": 1363,           // ⚠️ Heavily reported
  "is_tor": true,                  // ⚠️ Anonymization
  "risk_level": "CRITICAL"
}
```
> "THIS would be a red flag - 100% abuse score with Tor usage!"

### Part 4: Generate Investigation Report (5 minutes)

**What to say**:
> "Now let's package all these findings into a professional report for management."

**What to do**:

**4.1 Create JSON Investigation Export**
```
Copilot, export the investigation data for user@contoso.com as JSON
```

**What Copilot generates**:
- File: `reports/investigation_user_2026-01-16.json`
- Contains:
  - User profile (name, department, roles)
  - All sign-in activity (last 7 days)
  - Anomaly detections
  - IP enrichment data
  - Risk assessment
  - Recommended actions

**4.2 Generate HTML Report**
```
Copilot, create an HTML report from this investigation
```

**Show the HTML report** (`reports/investigation_user_2026-01-16.html`):

**Key sections to highlight**:

1. **Executive Summary**:
   - "Investigated impossible travel alert for user@contoso.com"
   - "Finding: Legitimate business travel to Nigeria"
   - "Risk Level: LOW"
   - "Recommended Action: Monitor, no immediate action required"

2. **Timeline View**:
   ```
   08:00 UTC - User authenticated via MFA in Seattle, US
   08:30 UTC - User accessed Outlook from Lagos, NG (same session)
   ```

3. **IP Analysis Table**:
   | IP Address | Location | Abuse Score | VPN | Risk Level |
   |------------|----------|-------------|-----|------------|
   | 198.51.100.50 | Seattle, US | 0% | Yes (Corporate) | Clean |
   | 102.89.23.45 | Lagos, NG | 12% | No | Low |

4. **Risk Assessment**:
   - ✅ Initial authentication from trusted location
   - ✅ MFA verified at session start
   - ✅ No malicious IP indicators
   - ℹ️ Geographic anomaly (Seattle → Lagos) explained by session continuity

5. **Recommended Actions**:
   - [ ] No immediate action required
   - [ ] Monitor user for next 48 hours
   - [ ] Confirm travel with user if needed

**4.3 Export Investigation Data** (bonus if time permits)
- Ask Copilot: `Generate a report for this investigation`
- Show the generated HTML report with dark theme styling
- "Ready to share with executives or attach to tickets"

**Demo complete!** ✅

---

## Demo Scenarios by Skill Level

### For Beginners (Never Used Security Tools)

**Scenario**: "I'm new to cybersecurity. Show me the absolute basics."

**What to demonstrate**:

1. **Basic Concept - What is an Investigation?**
   - "Someone reported their email was hacked"
   - "We need to check: Did someone else log into their account?"
   - "If yes, what did they access?"

2. **Show Sample Data** (5 min)
   - Open `labs/sample-data/incidents/phishing_incident_sample.json`
   - Explain in plain language:
     - "This is what a phishing email looks like in our system"
     - "`sender: noreply@suspicious-domain.com` - fake email address"
     - "`url: http://malicious-site.com/login` - fake login page"
     - "`ips: ["185.220.101.45"]` - attacker's computer address"

3. **One-Click Investigation** (5 min)
   - "Let me show you how AI can do all the work"
   - Ask Copilot: `What incidents happened today?`
   - Show the simple English response
   - **Key message**: "You don't need to be a programmer to investigate"

4. **Show a Simple Report** (5 min)
   - Open any existing HTML report
   - Walk through visually:
     - "Red = bad, green = good"
     - "This map shows where the attacker logged in from"
     - "This timeline shows what they did minute-by-minute"

**Avoid**:
- ❌ Don't show KQL queries (too technical)
- ❌ Don't explain JSON syntax
- ❌ Don't mention MCP, APIs, or protocols
- ✅ Do focus on: "AI does the work, you read the results"

---

### For SOC Analysts (Some Experience)

**Scenario**: "I know basic security operations. Show me how this makes my job easier."

**What to demonstrate**:

1. **The Manual Way (Current State)** (3 min)
   - "Currently, you'd have to:"
     - Open Defender portal → find the incident
     - Open Azure AD portal → check sign-in logs
     - Open Sentinel → write KQL queries
     - Open 3 different threat intel websites
     - Copy/paste data into Word document
     - "This takes 30-60 minutes per investigation"

2. **The CyberProbe Way (Future State)** (7 min)
   - Ask Copilot: `Investigate user@contoso.com for last 7 days`
   - Watch it automatically:
     - Query Defender XDR
     - Query Azure AD
     - Run Sentinel KQL
     - Enrich IPs via API
     - Generate formatted report
   - "Same investigation, now 90 seconds"

3. **Show the Queries It Runs** (10 min)
   - Open `Investigation-Guide.md` Section 8
   - Show Query 1 (Priority IP Extraction):
     ```kql
     let target_upn = "user@contoso.com";
     union SigninLogs, AADNonInteractiveUserSignInLogs
     | where UserPrincipalName =~ target_upn
     | summarize SignInCount = count() by IPAddress
     | order by SignInCount desc
     | take 10
     ```
   - "This query finds the top 10 IPs the user signed in from"
   - "You can run this manually if needed, OR let Copilot do it"

4. **Customization Options** (5 min)
   - "You can modify the queries:"
     - Change `| take 10` to `| take 20` for more results
     - Change `ago(7d)` to `ago(30d)` for longer time window
     - Add `| where Country != "US"` to filter out domestic IPs
   - "Copilot will use your customized versions"

5. **Integration with Existing Workflow** (5 min)
   - "CyberProbe exports JSON and Excel"
   - "Import into your existing ticketing system (ServiceNow, Jira, etc.)"
   - "Can run on-demand or scheduled (e.g., daily batch of investigations)"

**Focus on**:
- ⏱️ Time savings: "60 minutes → 90 seconds"
- 🔁 Repeatability: "Same steps every time, no human error"
- 📚 Knowledge capture: "Junior analysts can investigate like seniors"

---

### For Advanced SOC Analysts / Threat Hunters

**Scenario**: "I write custom KQL queries daily. Show me advanced capabilities."

**What to demonstrate**:

1. **Advanced Authentication Analysis** (10 min)
   - Show SessionId-based forensic tracing (Investigation-Guide Section 9)
   - Demonstrate impossible travel analysis:
     - "User authenticated with MFA in Seattle at 08:00"
     - "Same session seen in Lagos at 08:30"
     - "SessionId proves it's token reuse, not new compromise"
   - **Advanced technique**: Time-window correlation when SessionId is empty
     ```kql
     // Fallback when SessionId is null
     let anomaly_time = datetime(2026-01-16T08:30:00Z);
     union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
     | where TimeGenerated between ((anomaly_time - 5min) .. (anomaly_time + 5min))
     | where UserPrincipalName =~ 'user@contoso.com'
     | order by TimeGenerated asc
     ```

2. **Custom MCP Tool Integration** (8 min)
   - Show the MCP architecture diagram
   - Demonstrate programmatic access:
     ```python
     from mcp import DefenderXDRClient
     
     client = DefenderXDRClient()
     incidents = client.list_incidents(
         severity="High",
         created_after="2026-01-15",
         top=100
     )
     ```
   - "You can integrate this into SOAR platforms (Cortex XSOAR, Splunk Phantom)"

3. **Advanced Hunting Queries** (7 min)
   - Show Query 11 (Threat Intel Bulk Enrichment):
     ```kql
     let target_ips = dynamic(["IP1", "IP2", ..., "IP50"]);  // Batch processing
     ThreatIntelIndicators
     | where NetworkSourceIP in (target_ips)
     | summarize arg_max(TimeGenerated, *) by NetworkSourceIP
     ```
   - "Batch query for 50 IPs takes ~28 seconds"
   - "Individual queries (50 × 28s) would take 23 minutes"
   - **Performance tip**: Always use batch dynamic arrays

4. **Custom Agent Skills** (10 min)
   - Show how to create a new skill:
     ```markdown
     ---
     name: lateral-movement-analysis
     description: Detect RDP/SMB lateral movement patterns
     ---
     # Lateral Movement Detection
     
     When user asks to detect lateral movement:
     1. Query DeviceNetworkEvents for RDP/SMB connections
     2. Build graph of source → destination relationships
     3. Identify pivot points (devices connecting to many targets)
     4. Flag anomalous patterns (e.g., workstation → domain controller)
     ```
   - "Save as `.github/skills/lateral-movement-analysis/SKILL.md`"
   - "Now Copilot knows how to detect lateral movement when you ask"

5. **HTML Report Generation** (5 min)
   - Ask Copilot: `Generate an executive report for the last 30 days`
   - Show the generated HTML dashboard with dark theme
   - "Creates professional reports with executive summary, timeline, risk charts"
   - "Track metrics: MTTR, incident volume by severity, top targeted users"

**Focus on**:
- 🔧 Extensibility: "Modify anything, add custom integrations"
- ⚡ Performance: "Optimized queries, batch processing"
- 🧩 Integration: "Fits into existing SIEM/SOAR workflows"
- 📊 Analytics: "Export to BI tools for trending and metrics"

---

## Queries You Can Run

Here are ready-to-use queries organized by use case. Copy/paste these into Copilot or Azure Sentinel.

### 1. **Find Users with Failed Sign-Ins**

**Use case**: Detect brute force attacks or password spraying

**Query**:
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"  // 0 = success, anything else = failure
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| where FailedAttempts > 5
| order by FailedAttempts desc
```

**How to run**:
- Ask Copilot: `Show me users with more than 5 failed sign-ins today`

**What it shows**:
| User | IP Address | Failed Attempts |
|------|------------|-----------------|
| admin@contoso.com | 45.142.120.1 | 23 |
| user@contoso.com | 185.220.101.45 | 12 |

**What to do next**:
- Check if the IPs are malicious: `python enrich_ips.py 45.142.120.1`
- If malicious, block the IP and force password reset

---

### 2. **Impossible Travel Detection**

**Use case**: Find sign-ins from geographically impossible locations

**Query**:
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "user@contoso.com"
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, IPAddress, City, Country, ResultType
| order by TimeGenerated asc
```

**How to run**:
- Ask Copilot: `Check if user@contoso.com has any impossible travel`

**What it shows**:
```
08:00 - Seattle, US
08:30 - Lagos, NG  ⚠️ (Impossible! 30 min to travel 7,500 miles)
```

**What to do next**:
- Run SessionId tracing to determine if it's token reuse or compromise
- Use Query from Section 9, Step 1

---

### 3. **Data Exfiltration Detection (Large File Uploads)**

**Use case**: Find users uploading unusually large amounts of data to cloud services

**Query**:
```kql
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType in ("FileUploaded", "FileCopied")
| extend FileSizeMB = todouble(ObjectSize) / 1048576  // Convert bytes to MB
| summarize TotalSizeMB = sum(FileSizeMB), FileCount = count() 
    by AccountObjectId, Application
| where TotalSizeMB > 1000  // More than 1GB
| order by TotalSizeMB desc
```

**How to run**:
- Ask Copilot: `Show me users who uploaded more than 1GB to cloud apps this week`

**What it shows**:
| User | App | Total Data | File Count |
|------|-----|------------|------------|
| insider@contoso.com | OneDrive | 3,500 MB | 247 files |

**What to do next**:
- Check user's recent sign-ins for geographic anomalies
- Review file names: `CloudAppEvents | where AccountObjectId == "..." | project ObjectId`
- Escalate to legal/HR if potential insider threat

---

### 4. **Admin Activity Monitoring**

**Use case**: Track what administrators are doing (role changes, permission grants)

**Query**:
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any (
    "Add member to role",
    "Add app role assignment",
    "Update application",
    "Add service principal"
  )
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Initiator, Target, Result
| order by TimeGenerated desc
```

**How to run**:
- Ask Copilot: `Show me admin actions from the last 24 hours`

**What it shows**:
```
10:00 - Add member to role - admin@contoso.com → newuser@contoso.com - Success
10:05 - Add service principal - admin@contoso.com → SuspiciousApp - Success ⚠️
```

**What to do next**:
- Verify the admin authorized these actions
- Check if "SuspiciousApp" is legitimate

---

### 5. **Phishing Email Investigation**

**Use case**: Find who received a phishing email and who clicked the link

**Query**:
```kql
EmailEvents
| where TimeGenerated > ago(7d)
| where SenderFromAddress has "suspicious-domain.com"
| project TimeGenerated, RecipientEmailAddress, Subject, SenderFromAddress
| join kind=inner (
    EmailUrlClickEvents
    | where TimeGenerated > ago(7d)
  ) on NetworkMessageId
| project TimeGenerated, RecipientEmailAddress, Subject, Url
```

**How to run**:
- Ask Copilot: `Who received emails from suspicious-domain.com and clicked links?`

**What it shows**:
| Time | Recipient | Subject | URL Clicked |
|------|-----------|---------|-------------|
| 09:15 | user1@contoso.com | "Password Reset Required" | http://evil.com/login |
| 09:18 | user2@contoso.com | "Password Reset Required" | http://evil.com/login |

**What to do next**:
- Check sign-in logs for both users after click timestamp
- Force password reset if suspicious sign-ins detected

---

### 6. **Check a Specific IP for Malicious Activity**

**Use case**: Quick IP reputation check using Microsoft's threat intelligence

**Query**:
```kql
let target_ip = "185.220.101.45";
ThreatIntelIndicators
| where NetworkSourceIP == target_ip
| where IsActive == true
| project TimeGenerated, ThreatType, Description, Confidence
| order by TimeGenerated desc
| take 5
```

**How to run**:
- Ask Copilot: `Is 185.220.101.45 in the threat intelligence database?`

**What it shows**:
```
ThreatType: Botnet C2
Description: Emotet command and control server
Confidence: 90
```

**What to do next**:
- Block the IP immediately
- Search for any connections to this IP: `DeviceNetworkEvents | where RemoteIP == "185.220.101.45"`

---

## Skills You Can Demonstrate

CyberProbe includes 5 pre-built Agent Skills. Here's how to demonstrate each one.

### Skill 1: **incident-investigation**

**Location**: `.github/skills/incident-investigation/SKILL.md`

**What it does**: Complete 5-phase user investigation workflow

**How to demonstrate**:
1. Open Copilot Chat
2. Type: `Investigate user@contoso.com for the last 7 days`
3. Watch as it automatically:
   - Gets user profile from Microsoft Graph
   - Runs 8 parallel KQL queries (sign-ins, anomalies, incidents, etc.)
   - Enriches all IP addresses
   - Generates JSON + HTML reports

**Key talking point**: 
> "This single command replaces 45-60 minutes of manual work across multiple portals."

**Show the output**:
- JSON file: `reports/investigation_user_2026-01-16.json`
- HTML report: `reports/investigation_user_2026-01-16.html`

---

### Skill 2: **threat-enrichment**

**Location**: `.github/skills/threat-enrichment/SKILL.md`

**What it does**: Multi-source IP threat intelligence lookup

**How to demonstrate**:
1. Ask Copilot: `Is 185.220.101.45 malicious?`
2. Watch as it:
   - Calls AbuseIPDB API
   - Calls IPInfo API
   - Calls VPNapi API
   - Combines results into risk assessment

**Key talking point**:
> "Instead of manually checking 3 different websites, one question gets all the data."

**Show the output**:
```
IP: 185.220.101.45
├─ Abuse Score: 100% (CRITICAL)
├─ Location: Russia
├─ ISP: Hosting Provider (suspicious)
├─ VPN/Tor: Yes
├─ Total Reports: 1,363
└─ Risk Level: CRITICAL - Block immediately
```

---

### Skill 3: **kql-sentinel-queries**

**Location**: `.github/skills/kql-sentinel-queries/SKILL.md`

**What it does**: Optimized KQL query library with 11 pre-built queries

**How to demonstrate**:
1. Ask Copilot: `Show me sign-ins from unusual locations for user@contoso.com`
2. Copilot activates the skill and uses Query 3b (Sign-ins by Location)
3. Runs the query automatically on Sentinel

**Key talking point**:
> "Analysts don't need to memorize KQL syntax. Just ask in plain English."

**Show the query it runs**:
```kql
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where UserPrincipalName =~ "user@contoso.com"
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize SignInCount = count() by City, Country
| order by SignInCount desc
```

---

### Skill 4: **microsoft-learn-docs** 🆕

**Location**: `.github/skills/microsoft-learn-docs/SKILL.md`

**What it does**: Access official Microsoft documentation and remediation guidance in real-time

**How to demonstrate**:

**Scenario**: Investigation reveals malicious OAuth application attack

**Part A: Search for Remediation Guidance**
1. Ask Copilot: `How do I revoke malicious OAuth applications in Entra ID?`
2. Watch as it:
   - Searches Microsoft Learn documentation
   - Returns official remediation playbooks
   - Provides step-by-step procedures from Microsoft security team

**Key talking point**:
> "No more Googling during incidents - Copilot retrieves official Microsoft guidance automatically."

**Show the results**:
```
Found: "Detect and Remediate Illicit Consent Grants"
Source: https://learn.microsoft.com/en-us/entra/identity/...

Official Steps:
1. Identify the malicious application
2. Disable the application (not delete - prevents re-consent)
3. Remove OAuth2 permission grants
4. Notify affected users
5. Monitor for re-authorization attempts
```

**Part B: Get Production-Ready Code**
1. Ask Copilot: `Show me PowerShell code to revoke OAuth consent grants`
2. Watch as it:
   - Searches Microsoft Learn code samples
   - Filters by language (PowerShell)
   - Returns production-tested cmdlets from official documentation

**Show the code**:
```powershell
# From Microsoft Learn - Official Microsoft.Graph PowerShell
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All"

# List all OAuth2 consent grants for suspicious app
Get-MgOauth2PermissionGrant -Filter "clientId eq '<app-id>'"

# Revoke the malicious grant
Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <grant-id>

# Revoke user sessions to force re-authentication
Revoke-MgUserSignInSession -UserId <user-id>
```

**Part C: Block TOR Networks (Advanced Demo)**
1. Investigation shows user authenticated from TOR exit nodes
2. Ask Copilot: `Find Microsoft documentation for blocking TOR networks with Conditional Access`
3. Watch as it retrieves:
   - Official Conditional Access configuration guides
   - PowerShell code to create named locations for anonymization networks
   - Best practices for blocking risky sign-in patterns

**Key talking point**:
> "This ensures we're always following Microsoft's latest security recommendations - not outdated blog posts or Stack Overflow answers."

**Integration Example**:
During the investigation workflow, when malicious activity is detected:
```
1. Detection: "Suspicious OAuth app 'Micr0s0ft-App' created from TOR IP"
2. Automatic documentation lookup:
   - OAuth revocation procedures
   - TOR blocking guidance
   - Compromised user investigation playbook
3. Report includes official Microsoft Learn URLs for compliance
4. Analyst executes vetted PowerShell commands from official docs
```

**Show the benefit**:
- ✅ **Speed**: Get remediation guidance in seconds vs 15-20 min Googling
- ✅ **Accuracy**: Official Microsoft procedures, not third-party interpretations
- ✅ **Compliance**: Cite authoritative sources in audit reports
- ✅ **Current**: Always reflects latest security features and updates
- ✅ **Multi-Product**: Covers Defender, Entra ID, Sentinel, Microsoft 365

---

### Skill 5: **report-generation**

**Location**: `.github/skills/report-generation/SKILL.md`

**What it does**: Create professional HTML reports + JSON data exports

**How to demonstrate**:

**Part A: Investigation Report**
1. Ask Copilot: `Create a report for the investigation we just ran`
2. It generates: `reports/investigation_user_2026-01-16.html`
3. Open the HTML file and show:
   - Dark theme professional styling
   - Executive summary section
   - IP analysis tables
   - Risk assessment charts
   - Recommended actions

**Part B: Incident Report**
1. Ask Copilot: `Create a critical incident report for incident #41272`
2. It generates: `reports/incident_41272_critical_report.html`
3. Show:
   - MITRE ATT&CK tactic mapping
   - Timeline visualization
   - Affected entities section
   - Remediation playbook

**Part C: JSON Data Export**
1. Ask Copilot: `Export investigation data for the last 7 days`
2. It generates a JSON file in `reports/`
3. Show the JSON file with structured data:
   - Incidents table
   - Alerts table
   - Entities table
   - Timeline table

**Key talking point**:
> "These reports are ready to send to executives or import into dashboards. No manual formatting needed."

---

## Common Demo Pitfalls

**Problem**: Copilot doesn't activate the skills

**Solution**:
- Ensure you're in the CyberProbe workspace folder
- Restart VS Code to reload skills
- Use trigger phrases like "investigate", "enrich", "query", "create report"

---

**Problem**: MCP tools return "Authentication failed"

**Solution**:
- Check if you're authenticated to Azure CLI: `az login`
- Verify MCP server is running (check VS Code status bar)
- Re-authenticate: `az account clear` then `az login`

---

**Problem**: KQL queries timeout

**Solution**:
- Reduce the time window: Change `ago(30d)` to `ago(7d)`
- Add `| take 100` to limit results
- Check Sentinel workspace isn't throttled

---

**Problem**: IP enrichment fails

**Solution**:
- Check API keys in `enrichment/config.json`
- Verify rate limits (AbuseIPDB: 1,000/day free tier)
- Test one IP at a time first: `python enrich_ips.py 8.8.8.8`

---

**Problem**: Report generation shows "No data"

**Solution**:
- Verify the investigation JSON was created first
- Check date range - might be no activity in selected timeframe
- Ensure user UPN is spelled correctly

---

**Problem**: Sample data queries return no results

**Solution**:
- Sample data is in JSON files, not Sentinel database
- Use sample files for training, not live queries
- For live demos, use actual production data or test tenant

---

## Demo Setup Checklist

### Pre-Demo (30 minutes before)

- [ ] **Test Azure authentication**:
  ```powershell
  az login
  az account show
  ```

- [ ] **Verify MCP server running**:
  - Check VS Code status bar for MCP indicator
  - Restart VS Code if needed

- [ ] **Test Copilot connection**:
  - Open Copilot Chat (`Ctrl+Shift+I`)
  - Ask: `What skills do you have available?`
  - Should see: incident-investigation, threat-enrichment, kql-sentinel-queries, report-generation

- [ ] **Prepare sample data**:
  - Navigate to `labs/sample-data/`
  - Have `phishing_incident_sample.json` ready to show
  - Have `test_user_profile.json` ready to show

- [ ] **Test IP enrichment**:
  ```powershell
  cd enrichment
  python enrich_ips.py 8.8.8.8  # Test with Google DNS (should be clean)
  ```

- [ ] **Pre-generate a sample report**:
  ```powershell
  # If you have test data, run an investigation now
  # Open in browser to verify it looks good
  ```

- [ ] **Clear old reports** (optional):
  - Delete old reports from `reports/` folder to avoid confusion
  - Or keep 1-2 good examples to show

- [ ] **Prepare backup slides**:
  - In case live demo fails, have screenshots of:
    - Sample report HTML
    - IP enrichment results
    - KQL query output
    - HTML dashboard report

### During Demo

- [ ] **Have Investigation-Guide.md open**: Section 8 (Queries) and Section 18 (Skills)
- [ ] **Have sample-data folder open**: Ready to show examples
- [ ] **Terminal ready**: PowerShell in `enrichment/` directory
- [ ] **Browser open**: To display generated HTML reports
- [ ] **Copilot Chat open**: `Ctrl+Shift+I`

### Post-Demo Q&A Prep

**Common questions and answers**:

**Q: "How much does this cost?"**
A: "CyberProbe is free and open source. You need Microsoft Defender XDR (E5 license) and Sentinel (pay-per-GB ingestion). The enrichment APIs have free tiers (AbuseIPDB: 1,000 queries/day, IPInfo: 50,000/month)."

**Q: "Can we use this with on-premises Active Directory?"**
A: "Partially. You can investigate Azure AD/Entra ID users. For on-prem AD, you'd need to sync logs to Sentinel first."

**Q: "Does this replace our SIEM?"**
A: "No, it complements it. CyberProbe queries your existing Sentinel/Defender data. Think of it as an investigation assistant, not a replacement SIEM."

**Q: "How long does setup take?"**
A: "About 2 hours for full setup:
- 30 min: Install prerequisites (Python, VS Code, GitHub Copilot)
- 30 min: Configure API keys
- 30 min: Test MCP server connection to Azure
- 30 min: Run through Lab 101"

**Q: "What if we don't have GitHub Copilot?"**
A: "You can still use CyberProbe manually - run the Python scripts and KQL queries yourself. Copilot adds automation, but the queries and enrichment work standalone."

**Q: "Can we customize the queries?"**
A: "Yes! All queries are in `Investigation-Guide.md` Section 8. Modify them, add new ones, and Copilot will use your customized versions."

**Q: "Is this Microsoft-supported?"**
A: "CyberProbe is a community project, not officially supported by Microsoft. However, it uses only official Microsoft APIs (Defender XDR, Sentinel, Graph)."

---

## Next Steps After Demo

**For immediate trial**:
1. Complete [Lab 101 - Getting Started](./101-getting-started/)
2. Try a sample investigation with your own test user

**For pilot deployment**:
1. Work through [Labs 102-106](./README.md) (Fundamentals series)
2. Set up API keys in `enrichment/config.json`
3. Test with 5-10 real user investigations
4. Measure time savings vs. manual process

**For full deployment**:
1. Complete all 10 labs (100-series + 200-series)
2. Create custom Agent Skills for your organization's specific playbooks
3. Integrate with ticketing system (ServiceNow, Jira)
4. Set up scheduled automation (e.g., daily batch investigations of high-risk users)
5. Create custom HTML dashboards for metrics tracking

**Resources**:
- [Investigation-Guide.md](../Investigation-Guide.md) - Complete query reference
- [README.md](./README.md) - Full lab catalog
- [.github/skills/](../.github/skills/) - Agent Skills documentation
- [enrichment/README.md](../enrichment/README.md) - IP enrichment setup guide

---

**Questions?** Open an issue on GitHub or refer to the [Troubleshooting Guide](../Investigation-Guide.md#16-troubleshooting-guide).

**Ready to start?** Jump to [Lab 101 - Getting Started](./101-getting-started/) →
