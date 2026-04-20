---
name: kql-auto-investigate
description: Fully-automated KQL investigation loop. Given a single entity (UPN, IP, device name, or incident ID), runs a scripted 3-phase investigation — triage, deep-dive, correlation — enriches IPs, and emits a JSON + HTML report without requiring user guidance between steps. Use when the user says "auto-investigate", "full investigation on", "deep dive on", or wants hands-off end-to-end analysis of a single entity.
---

# Automated KQL Investigation Skill

This skill is a **hands-off wrapper** that chains existing skills (`incident-investigation`, `threat-enrichment`, `report-generation`) into a single deterministic run. It exists so a user can say *"auto-investigate jdoe@contoso.com"* and get a complete report without guiding each step.

## When to Use This Skill

Trigger keywords: `auto-investigate`, `full investigation`, `deep dive on`, `run a complete investigation`, `investigate end-to-end`.

Use when:
- User provides a single entity (UPN, IP address, device hostname, or incident ID) and expects a complete report
- You are being invoked by another skill as a secondary step
- A scheduled / batch context (no user available to answer clarifying questions)

Do **not** use when:
- The user is asking an open-ended question that needs clarification
- Multiple entities need individual analysis (run per-entity instead)
- The investigation scope is broader than a single entity (use `incident-correlation-analytics`)

## Global Rule Inheritance

This skill inherits all global rules from [`.github/copilot-instructions.md`](../../copilot-instructions.md):

- 🔴 **Sentinel Workspace Selection** — Must select workspace before Phase 1
- 🔴 **KQL Pre-Flight Checklist** — Queries come from verified sources only (skills + `queries/` library)
- 🔴 **Evidence-Based Analysis** — Never invent data, cite every finding
- 🔴 **Known Table Pitfalls** — Use verified join patterns (SecurityAlert → SecurityIncident)

## Entity Type Detection

Before starting, classify the input:

| Input Pattern | Entity Type | Primary Skill |
|---------------|-------------|---------------|
| Contains `@` | UPN | `incident-investigation` (5-phase user workflow) |
| Matches `^\d{1,3}(\.\d{1,3}){3}$` or IPv6 | IP | `threat-enrichment` + IP-centric KQL |
| Matches `^[A-Z0-9-]+$` (no dots) or hostname | Device | `endpoint-device-investigation` |
| Matches `^INC-?\d+$` or 32+ hex chars | Incident ID | `incident-investigation` (incident workflow) |

## 3-Phase Workflow

### Phase 1 — Triage (parallel, ~30s)

**Read `enrichment/config.json`** for workspace name + ID, then run these queries in parallel via Sentinel Data Lake MCP (`query_lake`):

| Query | Table | Purpose |
|-------|-------|---------|
| T1 | `SigninLogs` | Last 7d sign-ins for entity (success + failure) |
| T2 | `SecurityAlert` | Alerts where `Entities has '<entity>'` |
| T3 | `AuditLogs` | Actions initiated by or targeting entity |
| T4 | `OfficeActivity` | Mailbox/file ops (if UPN) |

**Exit criteria:**
- All 4 queries return 0 results → emit clean report and **stop**
- ≥1 query returns results → proceed to Phase 2
- 2+ MCP failures → switch to Graph API fallback (see global rule)

### Phase 2 — Deep Dive (conditional, ~60s)

Run only the branches triggered by Phase 1 findings:

| Phase 1 Finding | Phase 2 Action |
|-----------------|----------------|
| Risky sign-ins (RiskState != "none") | `AADUserRiskEvents` + SessionId chain trace |
| Security alerts found | Join `SecurityAlert` → `SecurityIncident` via SystemAlertId to get real Status/Classification |
| Non-baseline IPs | Extract IPs, invoke `enrichment/enrich_ips.py` |
| Device activity found | Run `DeviceProcessEvents`, `DeviceNetworkEvents` via Advanced Hunting |
| Mailbox rule changes | Deep `OfficeActivity` filter on `New-InboxRule`, `Set-InboxRule` |

### Phase 3 — Correlation (~20s)

- **Baseline comparison**: Same-entity activity over last 30d vs Phase 1 window — flag new ASNs, countries, devices
- **Peer correlation**: Same IPs/devices against `SecurityIncident` across tenant (last 7d)
- **MITRE mapping**: Tag findings with ATT&CK TTPs using `report-generation` skill's mapping table

## Output

Always produce both artifacts using `report-generation` skill conventions:

```
reports/investigation_<entity_prefix>_YYYY-MM-DD.json   # raw data + metadata
reports/investigation_<entity_prefix>_YYYY-MM-DD.html   # formatted report
```

The HTML report **must** include a Methodology section (tool stack, queries executed, data sources, fallback strategy — see user memory rule).

## Stop Conditions

| Condition | Action |
|-----------|--------|
| Phase 1 returns 0 rows across all 4 queries | Emit clean-result report, stop |
| Same MCP tool fails twice with generic error | Switch to Graph/Data Lake REST API fallback |
| User explicitly interrupts | Save partial JSON, stop |
| Total runtime > 10 min | Checkpoint to JSON, report timeout, stop |
| Any PII leak detected in output | Replace with placeholder, log warning |

## Sub-skills Invoked

| Sub-skill | Purpose | When |
|-----------|---------|------|
| `incident-investigation` | 5-phase UPN or incident workflow | Entity is UPN or Incident ID |
| `endpoint-device-investigation` | Device forensics workflow | Entity is device hostname |
| `threat-enrichment` | IPInfo + AbuseIPDB + VPNapi + Shodan | Any IP extracted |
| `report-generation` | HTML + MITRE mapping | Always (Phase 3 output) |

## Example Invocation Patterns

| User Prompt | Entity | Phases Run |
|-------------|--------|-----------|
| "auto-investigate user@contoso.com" | UPN | 1 → 2 (all branches if hits) → 3 |
| "deep dive on 203.0.113.42" | IP | 1 (IP-scoped queries) → 2 (enrichment) → 3 |
| "full investigation on WORKSTATION-01" | Device | 1 (device triage) → 2 (process/network) → 3 |
| "run a complete investigation on INC-42" | Incident | 1 (incident entities) → fans out per entity |

## Driver Script (Optional)

For fully scripted / CI use, invoke the deterministic driver:

```powershell
python scripts/auto_investigate.py --entity user@contoso.com --days 7
```

The driver performs the same 3-phase workflow non-interactively, writes the JSON, and calls `enrich_ips.py`. The skill (this file) drives the Copilot/Claude interactive path; the script drives the headless path. Both converge on the same output format.

## Report Quality Checklist

Before emitting the HTML report, verify:

- [ ] Methodology section present with tool stack, queries, data sources
- [ ] No real UPNs, hostnames, tenant GUIDs (PII-free standard)
- [ ] Every claim tied to a specific query result (Evidence-Based rule)
- [ ] Risk levels cite ≥1 concrete finding (High: ≥2, Medium: ≥1, Low: explain)
- [ ] Explicit ✅ confirmations for empty sections ("No X found in Y")
- [ ] File naming follows `investigation_<prefix>_YYYY-MM-DD.{json,html}`
