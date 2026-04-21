# AI Attack Triage Playbook â€” Spec for Sentinel Playbook Generator

**Target feature:** [Generate playbooks using AI in Microsoft Sentinel (preview)](https://learn.microsoft.com/azure/sentinel/automation/generate-playbook)
**Language:** Python (Cline in embedded VS Code)
**Trigger:** Enhanced Alert Trigger on AI-related alerts
**Derived from:** `reports/investigation_user1_2026-04-21.json`

---

## 1. Enhanced Alert Trigger conditions

Create an Automation Rule with these trigger conditions:

| Field | Value |
|-------|-------|
| Provider | Azure Security Center Â· Microsoft 365 Insider Risk Management Â· Microsoft Data Loss Prevention |
| Alert Title contains any of | `ASCII smuggling`, `Jailbreak`, `Prompt Shields`, `user phishing attempt ... AI`, `AI Agent Reconnaissance`, `Risky AI usage`, `DSPM for AI`, `Restrict copilot by label` |
| Severity | Medium or High |
| Workspaces | Select all Sentinel workspaces where Defender for AI / Prompt Shields alerts land |

---

## 2. Required Integration Profiles

Create these in `Automation â†’ Integration Profiles` **before** running the generator:

| Name | Base URL | Auth | Scopes / Notes |
|------|----------|------|----------------|
| `Graph-Security` | `https://graph.microsoft.com` | OAuth2 Client Credentials | `https://graph.microsoft.com/.default` â€” needs `SecurityAlert.Read.All`, `SecurityIncident.ReadWrite.All`, `AuditLog.Read.All`, `User.Read.All`, `User.EnableDisableAccount.All` |
| `Graph-Defender-XDR` | `https://graph.microsoft.com` | OAuth2 | `ThreatHunting.Read.All`, `WindowsDefenderATP.Machine.Isolate` (for runHuntingQuery + isolation) |
| `AbuseIPDB` | `https://api.abuseipdb.com/api/v2` | API Key | Header `Key: <API_KEY>` |
| `IPInfo` | `https://ipinfo.io` | Bearer/JWT | Bearer token from ipinfo.io |
| `VPNapi` | `https://vpnapi.io/api` | API Key | Query param `?key=<KEY>` |
| `VirusTotal` (optional) | `https://www.virustotal.com/api/v3` | API Key | Header `x-apikey: <KEY>` |
| `Teams-Webhook` (optional) | Your Teams channel webhook URL | None (URL holds secret) | For SOC notifications |

---

## 3. Plan-mode prompt (paste this into Cline)

> Create a Python playbook that triages **AI-targeted attack alerts** from Microsoft Defender for Cloud / Prompt Shields / Purview DSPM for AI. Input is a single alert. The playbook must:
>
> **Step 1 â€” Extract entities from the alert:**
> - Primary user UPN and `id` (Entra object ID)
> - Source IP(s) from alert entities
> - Any `OAuthObjectId` or application/resource GUID present in alert properties
> - Alert MITRE tactics and techniques
>
> **Step 2 â€” Profile the user (Graph-Security + Graph-Defender-XDR):**
> - Get `/users/{upn}` (displayName, jobTitle, department, accountEnabled, createdDateTime)
> - Run an Advanced Hunting query via `POST /security/runHuntingQuery` with body `{"Query": "SigninLogs | where TimeGenerated > ago(30d) | where UserPrincipalName =~ '<UPN>' | summarize SignInCount=count(), SuccessRate=avg(iif(ResultType==0,1.0,0.0)), DistinctIPs=dcount(IPAddress), IPs=make_set(IPAddress,10) by bin(TimeGenerated,1d)"}`
> - Compute baseline: total sign-ins 30d, distinct IPs, daily failure-rate anomalies (flag any day where `SuccessRate < 0.5` AND `SignInCount > 50`)
> - For **each** source IP on the alert, check if it appears in the user's 30-day sign-in history. If it does NOT, flag as `ai_api_bypass = True` (AI endpoint hit without interactive auth â€” likely API key/token abuse).
>
> **Step 3 â€” Enrich every source IP in parallel (AbuseIPDB + IPInfo + VPNapi):**
> - AbuseIPDB: `GET /check?ipAddress=<IP>&maxAgeInDays=90` â†’ capture `abuseConfidenceScore`, `totalReports`, `isTor`, `isp`
> - IPInfo: `GET /<IP>/json` â†’ capture `city`, `country`, `org`, `asn`, `privacy` (vpn/proxy/hosting)
> - VPNapi: `GET /?ip=<IP>&key=<KEY>` â†’ capture `security.vpn/proxy/tor/relay`
> - Merge into one dict per IP. Compute a simple risk tag: HIGH if `abuseConfidenceScore >= 75`, MEDIUM if `>= 25` or `vpn=true` with `asn` not in corporate AS allowlist, else CLEAN.
>
> **Step 4 â€” Look up the OAuth/Resource GUID:**
> - Try Graph `GET /applications(appId='{guid}')` â€” if 404, try `GET /servicePrincipals(appId='{guid}')`
> - If both 404, run Advanced Hunting `AuditLogs | where TimeGenerated > ago(90d) | where tostring(TargetResources) has '{guid}'` â€” if also 0 hits, mark as `likely_azure_openai_resource_id = True` and add this explanation to the incident comment.
>
> **Step 5 â€” Cluster correlation (Advanced Hunting):**
> - Run `SecurityAlert | where TimeGenerated > ago(30d) | where AlertName has_any ("ASCII smuggling","Jailbreak","Prompt Shields","AI agent","Risky AI usage") | extend UserEntities = extract_all(@'"Name":"([^"]+)"', tostring(Entities)) | mv-expand UserEntities | summarize AlertCount=count(), AlertTypes=make_set(AlertName) by UserEntity=tostring(UserEntities) | where AlertCount > 1`
> - If the current user appears in this list, capture the cluster (all other users with â‰¥2 AI alerts in 30d) as `related_users`.
>
> **Step 6 â€” Compute final risk score:**
> - `risk = "HIGH"` if any of: (a) `ai_api_bypass == True` AND source IP has `abuseConfidenceScore >= 25`, (b) user has â‰¥3 AI attack alerts in 30d, (c) any IP tagged HIGH, (d) Purview IRM HIGH alert on same user in last 7d.
> - `risk = "MEDIUM"` if: single AI alert with VPN/proxy source OR user appears in cluster correlation.
> - Otherwise `risk = "LOW"`.
>
> **Step 7 â€” Build a structured incident comment (Markdown):**
> - Title: `ðŸ¤– AI Attack Triage â€” {AlertName}`
> - Sections: Executive Summary, Baseline Profile, Source IPs (table with geo/ASN/abuse/VPN flags), OAuth Object Analysis, Cluster Correlation, Risk, Recommended Actions, Methodology.
> - Post via `POST /security/incidents/{incidentId}/comments` with body `{"@odata.type":"microsoft.graph.security.alertComment","comment":"<markdown>"}`
>
> **Step 8 â€” Response actions gated by risk:**
> - If `risk == "HIGH"`:
>   - `PATCH /security/incidents/{incidentId}` to set `classification: unknown, severity: high, status: active`
>   - If `ai_api_bypass == True`: add tag `api-key-rotation-required` to the incident
>   - If user has HIGH-sev Purview IRM alert within 7 days: escalate by assigning incident to the Insider Risk queue (set `assignedTo: "insider-risk@contoso.com"`)
>   - Optionally post a Teams webhook notification with a summary and link to the incident
> - If `risk == "MEDIUM"`:
>   - Add incident comment + tag `ai-attack-watchlist`
>   - Do NOT take user actions
> - If `risk == "LOW"`:
>   - Add comment only
>
> **Step 9 â€” Return a JSON summary** with keys: `risk`, `ai_api_bypass`, `user_upn`, `baseline_signin_count_30d`, `distinct_baseline_ips`, `enriched_ips` (list of dicts), `oauth_resolution`, `related_users`, `actions_taken` (list), `incident_id`, `comment_posted` (bool).
>
> **Guardrails:**
> - Never automatically disable a user account or isolate a device in this playbook â€” those are one-way doors that belong in a separate high-confidence playbook.
> - All external API calls must have retries with exponential backoff (max 3 attempts) and a 10-second per-request timeout.
> - Never log secrets; redact API keys from any debug output.
> - Do NOT include PII in the return value logs â€” only in the incident comment.
>
> Generate a visual flow diagram and Markdown documentation describing each step.

---

## 4. Test harness

When Cline enters **Act mode** and asks for an Alert ID for testing, use one of these alerts from the user1 investigation as a known-good input:

| Alert | Expected risk outcome |
|-------|-----------------------|
| `Suspected prompt injection using ASCII smuggling detected` (2026-04-17) | HIGH (ai_api_bypass true, 3 alerts same day) |
| `A Jailbreak attempt on your Azure AI model deployment was detected by Prompt Shields` (2026-04-17) | HIGH |
| `AI Agent Reconnaissance Attempt Detected (Preview)` (2026-04-15) | MEDIUM (single low-sev alert, VPN source) |

---

## 5. Validation checklist

After generation, manually verify:

- [ ] No hardcoded tenant IDs, UPNs, or GUIDs (all read from alert/env)
- [ ] Retry + timeout wrappers on every HTTP call
- [ ] Secrets fetched from integration profile, not embedded
- [ ] Incident comment stays under 30 KB (Markdown), truncate if longer
- [ ] `risk` decision tree has an explicit default branch (no silent fallthrough)
- [ ] Unit-test-style assertions in the generated test harness cover: HIGH, MEDIUM, LOW paths

---

## 6. Mapping to the investigation we just performed

| Manual step (user1 investigation) | Playbook equivalent |
|----------------------------------|---------------------|
| `query_lake` SigninLogs 30d baseline | Step 2 â€” runHuntingQuery SigninLogs |
| `query_lake` SigninLogs for attacker IP | Step 2 â€” `ai_api_bypass` check |
| `query_lake` SecurityAlert joined entities | Step 5 â€” cluster correlation |
| `python enrich_ips.py` | Step 3 â€” parallel IP enrichment |
| `query_lake` AuditLogs for OAuth object ID | Step 4 â€” GUID resolution |
| Risk rating paragraph in report | Step 6 â€” risk computation |
| Methodology section in report | Step 7 â€” Markdown comment |
| Manual SOC recommendation | Step 8 â€” gated response actions |

---

## 7. Follow-on playbooks (suggested)

Once the triage playbook is stable, generate these as separate playbooks (one-way actions isolated by design):

1. **AI Attack Containment** â€” rotates Azure OpenAI / Cognitive Services keys, requires a `HIGH-confirmed` tag on the incident as a guard.
2. **Prompt Shields Posture Check** â€” scheduled (not alert-driven); runs Advanced Hunting across `CloudAuditEvents` for Foundry deployments in Detect-only mode and opens a remediation incident per gap.
3. **AI Abuse Cluster Sweep** â€” takes a cluster of related users from Step 5 above and runs the triage playbook on each recent alert they own.

