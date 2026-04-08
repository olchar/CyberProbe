# Introducing CyberProbe: Open-Source AI-Powered Security Investigations for Microsoft Defender XDR & Sentinel

**TL;DR** — CyberProbe is an open-source investigation platform that turns GitHub Copilot into a SOC analyst. It includes 11 AI agent skills, 40+ battle-tested KQL queries, hands-on labs, multi-source threat enrichment, and interactive MCP-powered report generation — all wired into Microsoft Defender XDR and Sentinel via Model Context Protocol.

**[GitHub: CyberProbe →](https://github.com/YOUR_ORG/CyberProbe)**

---

## The Problem

Security Operations Centers are drowning. The average SOC analyst faces hundreds of alerts per day, each requiring context from multiple data sources — sign-in logs, endpoint telemetry, threat intelligence feeds, audit trails. The investigation process is manual, repetitive, and error-prone:

1. Pull incident details from Defender XDR
2. Query Sentinel for related sign-in activity
3. Cross-reference IPs against threat intel (AbuseIPDB, Shodan, IPInfo...)
4. Check for lateral movement across endpoints
5. Map findings to MITRE ATT&CK
6. Write the report

An experienced analyst might take 30–60 minutes per incident. A junior analyst? Significantly longer — and they might miss critical context.

**What if your AI coding assistant could do all of this in under 6 minutes?**

---

## What is CyberProbe?

CyberProbe is an open-source platform that transforms GitHub Copilot (and other AI assistants) into a specialized security investigation agent. Built on [VS Code Agent Skills](https://agentskills.io) and [Model Context Protocol (MCP)](https://modelcontextprotocol.io), it provides the domain knowledge, query libraries, and automation workflows that AI needs to conduct professional-grade investigations.

Think of it as **"security analyst in a box"** — except the box is your VS Code editor.

### What's Inside

| Component | What It Does |
|-----------|-------------|
| **11 Agent Skills** | Specialized investigation workflows — incident triage, threat hunting, endpoint forensics, exposure management, IOC lifecycle, response actions |
| **40+ KQL Queries** | Battle-tested Kusto queries for identity compromise, attack paths, SOC metrics, email threats, and more |
| **10 Hands-On Labs** | From beginner (30 min) to advanced scenarios (90 min) — phishing campaigns, compromised identities, insider threats, data exfiltration |
| **Threat Enrichment Engine** | Multi-source IP/IOC enrichment via AbuseIPDB, IPInfo, VPNapi, Shodan, and VirusTotal |
| **MCP App Suite** | Interactive visualizations — IP threat maps, entity explorers, response action consoles, security posture dashboards |
| **Security Copilot Agents** | Pre-built YAML agent definitions for Microsoft Security Copilot |
| **Report Templates** | Dark-themed HTML reports with MITRE ATT&CK mapping, timelines, and executive summaries |
| **Power BI Integration** | Automated data export for executive dashboards and trend analysis |

---

## How It Works

CyberProbe follows Microsoft's **"Anatomy of a Security Agent"** architecture pattern:

```
User: "Investigate incident 55843"
         │
         ▼
┌─ ORCHESTRATION ──────────────────────────────┐
│  copilot-instructions.md detects the keyword │
│  "investigate incident" → loads the          │
│  incident-investigation skill                │
└──────────────────────────────────────────────┘
         │
         ▼
┌─ KNOWLEDGE ──────────────────────────────────┐
│  MCP servers provide live data:              │
│  • Sentinel Data Lake (KQL queries)          │
│  • Defender XDR (incidents, alerts, hunting) │
│  • Microsoft Graph (users, devices, sign-ins)│
│  • Microsoft Learn (remediation playbooks)   │
└──────────────────────────────────────────────┘
         │
         ▼
┌─ SKILLS ─────────────────────────────────────┐
│  5-phase investigation workflow:             │
│  1. Retrieve incident + alert details        │
│  2. Query sign-ins, audit logs, endpoints    │
│  3. Enrich IPs with threat intelligence      │
│  4. Correlate findings + risk scoring        │
│  5. Generate HTML report with MITRE mapping  │
└──────────────────────────────────────────────┘
         │
         ▼
    Investigation complete in ~5 minutes
    HTML report + JSON data saved to reports/
```

The key insight: **you don't need to learn the skills system**. Just talk to Copilot in natural language:

- *"Investigate incident 55843"* → full 5-phase investigation
- *"Is 203.0.113.42 malicious?"* → multi-source threat enrichment
- *"Check the device WORKSTATION-01 for threats"* → endpoint forensics
- *"Show me SOC metrics for the last 30 days"* → campaign detection + MTTD/MTTR analysis
- *"What's our exposure posture?"* → CTEM metrics, choke points, attack paths

CyberProbe detects the intent from your prompt and loads the right skill automatically.

---

## The Skills

### Core Investigation
- **incident-investigation** — Complete 5-phase automated workflow with parallel query execution, SessionId-based auth tracing, and IP enrichment
- **endpoint-device-investigation** — Defender for Endpoint forensics: processes, network connections, file operations, vulnerabilities, lateral movement detection
- **threat-enrichment** — Multi-source IP enrichment (AbuseIPDB, IPInfo, VPNapi, Shodan) with risk scoring
- **ioc-management** — IOC extraction, deduplication, watchlists, and SIEM/SOAR export

### Posture & Analytics
- **exposure-management** — CTEM metrics, CNAPP posture, attack surface inventory, choke points, attack paths, compliance
- **incident-correlation-analytics** — Campaign detection, heatmaps, MTTD/MTTA/MTTR metrics, top impacted users/devices

### Response & Reporting
- **defender-response** — Active containment: device isolation, user compromise marking, AV scans, forensic collection
- **report-generation** — HTML/JSON reports with dark theme, MITRE ATT&CK mapping, methodology sections, executive briefings

### Tooling & Reference
- **kql-sentinel-queries** — Execute pre-built KQL queries against Sentinel
- **kql-query-builder** — AI-assisted KQL generation with 331+ table schema validation
- **microsoft-learn-docs** — Real-time Microsoft Learn lookups for remediation guidance

---

## Labs: Learn by Doing

CyberProbe includes **10 structured labs** with sanitized sample data, so you can learn without needing a production environment:

| Series | Labs | Focus |
|--------|------|-------|
| **100 — Fundamentals** | 6 labs (30–60 min each) | Setup, basic investigations, auth analysis, threat hunting, incident response, MCP automation |
| **200 — Real-World Scenarios** | 4 labs (90 min each) | Phishing campaigns, compromised identities, insider threats, data exfiltration |

Each lab includes step-by-step instructions, expected outputs, and a facilitator guide for workshop delivery.

---

## Getting Started

### Prerequisites
- VS Code with GitHub Copilot
- Microsoft Defender XDR and/or Sentinel access
- Python 3.9+ (for enrichment scripts)

### Quick Start

```bash
# Clone the repo
git clone https://github.com/YOUR_ORG/CyberProbe.git
cd CyberProbe

# Open in VS Code
code .

# Copy and configure your API keys
cp enrichment/config.json.template enrichment/config.json
# Edit config.json with your workspace ID, tenant ID, and API keys

# (Optional) Set up Python environment for enrichment scripts
python -m venv .venv
.venv/Scripts/Activate.ps1  # Windows
pip install -r enrichment/requirements.txt
```

That's it. Open Copilot Chat and type: *"Investigate incident 12345"*.

The MCP servers (Sentinel, Defender XDR, Microsoft Graph, Microsoft Learn) connect automatically through VS Code — no additional server setup required.

---

## What Makes This Different?

**This isn't another KQL query pack.** CyberProbe is a complete investigation *system* that teaches AI how to think like a SOC analyst:

- **Anti-hallucination guardrails** — Skills enforce evidence-based analysis. Every finding must cite specific query results. No "likely" or "probably" without data.
- **Known pitfall documentation** — Common KQL mistakes (like assuming `SecurityAlert.Status` reflects real status — it doesn't) are documented and enforced in every skill.
- **Automatic tool selection** — The system knows which tables live in Sentinel vs. Advanced Hunting, handles timestamp column differences, and falls back to REST APIs when MCP servers are unavailable.
- **Workspace selection safety** — Multi-workspace environments require explicit user confirmation before querying. No accidental cross-tenant queries.

---

## Contributing

CyberProbe is MIT-licensed and contributions are welcome. Some ideas:

- **New KQL queries** for emerging attack patterns
- **Additional skills** for specialized investigations (cloud infrastructure, container security, OT/IoT)
- **Lab scenarios** based on real-world campaigns (sanitized)
- **Enrichment source integrations** (new threat intel providers)
- **Localization** of labs and documentation

---

## Links

- **GitHub Repository**: [github.com/YOUR_ORG/CyberProbe](https://github.com/YOUR_ORG/CyberProbe)
- **VS Code Agent Skills Standard**: [agentskills.io](https://agentskills.io)
- **Model Context Protocol**: [modelcontextprotocol.io](https://modelcontextprotocol.io)
- **Microsoft Defender XDR**: [Microsoft Security](https://www.microsoft.com/security)

---

*CyberProbe is an open-source community project. It is not an official Microsoft product. Microsoft, Defender XDR, Sentinel, and Copilot are trademarks of the Microsoft Corporation.*
