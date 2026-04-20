# CyberProbe — Claude Code Instructions

You are a security investigation agent working in the **CyberProbe** repository.
This file is the entry point for [Claude Code](https://docs.anthropic.com/claude-code) sessions.
It mirrors the rules already followed by GitHub Copilot via [`.github/copilot-instructions.md`](.github/copilot-instructions.md).

---

## 📑 Primary Rule: Inherit Copilot Instructions

**All rules in [`.github/copilot-instructions.md`](.github/copilot-instructions.md) apply here.**
Read that file at the start of every session. In particular:

- 🔴 Sentinel Workspace Selection (ask before auto-selecting when multiple exist)
- 🔴 KQL Pre-Flight Checklist (verify schema, check skills/queries first)
- 🔴 Evidence-Based Analysis (never invent data, always cite queries)
- 🔴 Known Table Pitfalls (SecurityAlert.Status, SigninLogs dynamic fields, etc.)
- 🔴 Tool Selection Rule (Data Lake vs Advanced Hunting)

---

## 🔧 Environment Configuration

Environment-specific values live in [`enrichment/config.json`](enrichment/config.json) (gitignored).

**Always read `enrichment/config.json` before:**
- Running any Sentinel query (needs `sentinel_workspace_id`, `sentinel_workspace_name`)
- Calling enrichment APIs (`api_keys.ipinfo`, `api_keys.abuseipdb`, etc.)
- Referencing tenant context (`tenant_id`, `domain`)

Never hardcode workspace IDs, tenant GUIDs, or API keys in scripts or reports.

---

## 🤖 Available Skills

Skills live in [`.github/skills/`](.github/skills/). Detect the appropriate skill by matching trigger keywords in the user's prompt, then read the skill's `SKILL.md` before acting.

| Category | Skill | Trigger Keywords |
|----------|-------|------------------|
| Investigation | `incident-investigation` | "investigate incident", "incident ID", "triage" |
| Investigation | `endpoint-device-investigation` | "investigate device", "check machine", hostname |
| Investigation | `ioc-management` | "IOC", "watchlist", "threat intel feed" |
| Investigation | `threat-enrichment` | "enrich IP", "is this malicious" |
| Investigation | `incident-correlation-analytics` | "incident trends", "campaign", "MTTA" |
| Posture | `exposure-management` | "CTEM", "attack surface", "choke points", "CNAPP" |
| Response | `defender-response` | "isolate device", "containment" |
| Reporting | `report-generation` | "generate report", "executive summary" |
| Tooling | `kql-sentinel-queries` | "run KQL", "query Sentinel" |
| Tooling | `kql-query-builder` | "write KQL", "build query" |
| Tooling | `kql-auto-investigate` | "auto-investigate", "full investigation on", "deep dive on", "end-to-end" |
| Detection | `detection-engineering` | "convert sigma", "detection rule", "analytic rule" |
| Reference | `microsoft-learn-docs` | "Microsoft docs", "official guidance" |

---

## 🔌 MCP Servers

This repo ships [`.vscode/mcp.json`](.vscode/mcp.json) with the following servers. Claude Code will auto-discover them when launched from the workspace root:

| Server | Purpose |
|--------|---------|
| Sentinel Data Lake | `query_lake`, `search_tables`, `list_sentinel_workspaces` |
| Defender XDR Triage | Incidents, alerts, Advanced Hunting, entity investigation |
| Microsoft Graph | Entra, Defender REST API fallback |
| Microsoft Learn | Official docs & code samples |
| Azure MCP | Log Analytics, Resource Graph, subscription enumeration |
| GitHub | Repo, PR, issue operations |
| Sentinel Graph | Entity graph, blast radius |

**Fallback rule:** If an MCP call fails twice with a generic error, fall back to the Microsoft Graph Security API via `az rest` or `Invoke-RestMethod` (see copilot-instructions.md § MCP Unavailability).

---

## 📋 Report Conventions

Save all generated reports to [`reports/`](reports/) using the standard naming convention:

| Type | Pattern |
|------|---------|
| Investigation | `investigation_<upn_prefix>_YYYY-MM-DD.{json,html}` |
| IP enrichment | `ip_enrichment_<count>_ips_YYYY-MM-DD.json` |
| Incident | `incident_report_<id>_YYYY-MM-DD.html` |
| Executive | `executive_report_YYYY-MM-DD.html` |

**Every report MUST include a Methodology section** (tool stack, data extraction queries, data sources, fallback strategy). See [`.github/skills/report-generation/SKILL.md`](.github/skills/report-generation/SKILL.md).

### 🔴 Output Directory Rule — Real vs Fake Data

- **Real data** (live MCP queries, production tenant, real IPs, Microsoft demo tenants) → write to [`reports-private/`](reports-private/) (gitignored)
- **Fake data** (synthetic, sample, placeholder UPNs, templates) → write to [`reports/`](reports/)
- **Default when uncertain** → `reports-private/`. Never commit real investigation output.

---

## 🔒 PII-Free Standard

Committed documents must NEVER contain real:
- UPNs, email addresses, or display names
- Workspace names, hostnames, or server names
- Tenant IDs, subscription IDs, or object GUIDs
- Application names from live environments

Use generic placeholders: `user@contoso.com`, `<WorkspaceName>`, `<YourAppName>`.

Private output (reports derived from live/real data) belongs in [`reports-private/`](reports-private/) or [`scripts-private/`](scripts-private/), both gitignored. Synthetic/sample-data reports go in [`reports/`](reports/).

---

## 🛠️ Tool Priority

When multiple approaches are viable, prefer in this order:

1. **MCP servers** (typed, authenticated, schema-aware)
2. **Python scripts** in [`enrichment/`](enrichment/) and [`scripts/`](scripts/) (deterministic, reusable)
3. **Query library** in [`queries/`](queries/) (pre-verified KQL)
4. **PowerShell** for local Windows operations
5. **Terminal `az rest` / `Invoke-RestMethod`** as last-resort API fallback

---

## ⚠️ Safety Defaults

See [`.claude/settings.json`](.claude/settings.json) for the permission model. By default:

- ✅ Auto-allowed: read files, edit files, `git status/diff/log`, `python` and `pwsh` invocations
- ❓ Ask first: arbitrary shell commands, web fetches, destructive git ops
- ❌ Denied: `rm -rf`, `git push --force`, `git reset --hard`

Never bypass these defaults with `--no-verify`, `--force`, or similar flags without explicit user approval.
