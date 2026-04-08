# CyberProbe MCP Apps Server v2.0

Interactive security investigation tools with **inline UI rendering** for VS Code Copilot, powered by the MCP Apps specification.

## What's New in v2.0

This version implements the official [MCP Apps extension](https://modelcontextprotocol.github.io/ext-apps/api/) (spec 2026-01-26), enabling interactive UI components to render **directly in Copilot chat** instead of opening external browser panels.

### Before vs After

| v1.0 (Legacy) | v2.0 (MCP Apps) |
|---------------|-----------------|
| Text summary + external browser | Interactive map **inline in chat** |
| `_meta.ui/resourceUri` pattern | `registerAppTool` + `registerAppResource` |
| Manual HTML generation | Vite-bundled single-file HTML |
| No host communication | Full MCP Apps bridge for bidirectional data flow |

## Features

### 🌐 IP Threat Map (`analyze_ip_threats`)
- Real-time geographic visualization of malicious IPs
- Color-coded threat severity (Critical: Red, High: Orange, Medium: Yellow, Clean: Green)
- Click markers for detailed abuse reports
- Filter by risk level and location
- Integrates with AbuseIPDB, IPInfo, VPNapi, Shodan enrichment data

### 🔍 Entity Explorer (`explore_entities`)
- Interactive list of security entities (IPs, users, devices, alerts, IOCs)
- Filter by entity type, severity, and tags
- Search across all entity fields
- Drill-down details panel for each entity
- Supports 10 entity types: ip, user, device, domain, email, file, hash, url, process, alert

### 🛡️ Security Posture Dashboard (`security_posture_dashboard`)
- VM inventory with subscription breakdown (running vs deallocated)
- Defender for Servers P2 cost analysis and security ratio
- AV signature compliance tracking with days-behind metrics
- Exposure analysis with vulnerability counts per device
- Attack path visualization with choke point prioritization
- CSPM findings summary (high/medium/low)
- Blind spot detection for offline or stale devices
- MITRE ATT&CK technique mapping with evidence
- Prioritized remediation recommendations

### ⚡ Response Actions Console (`response_actions_console`)
- Device isolation and release tracking
- Identity containment actions (compromise marking, session revocation)
- Incident management (status updates, classification, tagging)
- Forensic collection package tracking
- Response playbook visualization with step-by-step progress
- Full action history with search and filter
- Status indicators: Succeeded, Pending, InProgress, Failed, Cancelled

## Quick Start

### 1. Install Dependencies
```bash
cd cyberprobe-mcp-apps
npm install
```

### 2. Build the Server
```bash
npm run build
```
This compiles TypeScript server code and bundles the UI into `dist/mcp-app.html`.

### 3. Configure VS Code
Add to your VS Code MCP settings (`settings.json`):
```json
{
  "mcp.servers": {
    "cyberprobe": {
      "command": "node",
      "args": ["<path-to-repo>/cyberprobe-mcp-apps/dist/index.js"],
      "env": {
        "CYBERPROBE_ROOT": "<path-to-repo>"
      }
    }
  }
}
```

### 4. Restart VS Code
The server will be available in GitHub Copilot chat.

## Usage

In VS Code Copilot chat:

```
Analyze these IPs for threats: 109.70.100.7, 176.65.134.8, 76.182.132.142
```

The agent will:
1. Call the IP enrichment tool
2. Render an interactive threat map
3. Display abuse scores, locations, and ISP information
4. Allow you to click markers for detailed analysis

## Available Tools

### `analyze_ip_threats`
Enriches IP addresses with threat intelligence and displays an interactive geographic map.

**Parameters:**
- `ips` (array, required): List of IPv4 addresses to analyze (max 50)

**Returns:** Interactive map with geographic markers, abuse scores, geolocation, ISP data, VPN/proxy detection, Shodan port/CVE data.

### `explore_entities`
Displays an interactive entity list for investigation findings.

**Parameters:**
- `entities` (array, required): Entity objects with `type`, `value`, `name`, `severity`, `tags`, and `details`
- `title` (string, optional): Title for the entity list

**Returns:** Interactive filterable/searchable entity list with drill-down details.

### `security_posture_dashboard`
Renders a comprehensive security posture dashboard for Defender for Servers.

**Parameters:**
- `vmInventory` (object, required): VM counts and subscription breakdown
- `costs` (object, required): P2 licensing and compute cost analysis
- `avCompliance` (object, required): AV signature status per device
- `exposure` (object, required): Vulnerability exposure per device
- `attackPaths` (object, required): Attack path counts and choke points
- `cspm` (object, required): CSPM finding counts by severity
- `blindSpots` (array, required): Offline/stale devices
- `mitre` (array, required): MITRE ATT&CK technique evidence
- `recommendations` (array, required): Prioritized remediation actions
- `title`, `reportDate` (string, optional)

**Returns:** Interactive dashboard + standalone HTML report saved to `reports/`.

### `response_actions_console`
Displays a response actions console for tracking containment and remediation.

**Parameters:**
- `actions` (array, required): Response action objects with `type` (device/identity/incident/forensic), `action`, `target`, `status`, and optional `details`
- `playbooks` (array, optional): Playbook definitions with steps and MCP tool names
- `title`, `reportDate` (string, optional)

**Returns:** Interactive console + standalone HTML report saved to `reports/`.

## Development

### Build
```bash
npm run build
```

### Watch Mode
```bash
npm run dev
```

### Test with Inspector
```bash
npm run inspector
```

## Architecture

```
cyberprobe-mcp-apps/
├── src/
│   ├── index.ts              # MCP server entry point (all 4 tools registered)
│   ├── app/
│   │   ├── ip-threat-map.ts  # Interactive map component
│   │   ├── entity-explorer.ts # Entity list component
│   │   ├── security-posture.ts # Posture dashboard component
│   │   └── response-actions.ts # Response console component
│   └── tools/
│       ├── analyze-ips.ts    # IP enrichment integration
│       └── entity-explorer.ts # Entity data transforms
├── mcp-app.html              # IP Threat Map UI template
├── entity-explorer.html      # Entity Explorer UI template
├── security-posture.html     # Security Posture UI template
├── response-actions.html     # Response Actions UI template
├── package.json
├── tsconfig.json
└── README.md
```

## Integration with CyberProbe

This MCP Apps server integrates with CyberProbe's investigation pipeline:

1. **Python Enrichment** (`../enrichment/enrich_ips.py`) — Calls AbuseIPDB, IPInfo, VPNapi, Shodan APIs
2. **MCP Server** (this project) — Exposes 4 tools to Copilot with inline UI rendering
3. **MCP Apps** — Interactive UI components rendered directly in VS Code Copilot chat
4. **HTML Reports** — Standalone reports auto-saved to `../reports/` and opened in browser

## Requirements

- Node.js 18+
- VS Code Insiders or VS Code 1.108+
- GitHub Copilot subscription
- CyberProbe enrichment configuration (`../enrichment/config.json`)

## License

MIT
