# CyberProbe Scripts

Automation and utility scripts for the CyberProbe platform.

## Contents

| File / Folder | Description |
|---------------|-------------|
| `check-mcp-health.ps1` | Verifies connectivity to all configured MCP servers (Data Exploration, Triage, Learn, GitHub, Sentinel Graph). Runs automatically on workspace open via VS Code task. |
| `remediation/` | Attack path remediation and Sentinel rule deployment scripts. See [remediation/README.md](remediation/README.md). |

## MCP Health Check

The health check script pings each MCP server endpoint and reports reachability:

```powershell
.\scripts\check-mcp-health.ps1
```

This is also configured as a VS Code task (`Check MCP Server Health`) that runs on folder open. See [../.vscode/tasks.json](../.vscode/tasks.json).

## Remediation Scripts

| Script | Purpose |
|--------|---------|
| `remediation/Remediate-AttackPaths.ps1` | PowerShell remediation for Defender for Cloud choke points |
| `remediation/Deploy-SentinelRules.ps1` | Deploy Sentinel analytics rules for attack path monitoring |

See [remediation/README.md](remediation/README.md) for details.

---

**Last Updated:** February 18, 2026
