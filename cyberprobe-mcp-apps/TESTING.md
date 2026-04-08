# MCP Apps Testing Guide

## Quick Test Commands

Once you've added the configuration and restarted VS Code, test with these prompts in Copilot Chat:

### Test 1: Basic IP Analysis
```
Analyze these IPs for threats: 109.70.100.7, 176.65.134.8
```

**Expected Result:**
- Text summary with threat statistics
- Interactive HTML UI showing:
  - Statistics dashboard (total, critical, high, medium, clean counts)
  - Data table with IP addresses, locations, abuse scores
  - Color-coded severity levels (red for critical, orange for high)

### Test 2: Multiple IPs
```
@cyberprobe analyze_ip_threats with these IPs: 109.70.100.7, 176.65.134.8, 20.232.172.13
```

### Test 3: Single IP Investigation
```
Is IP 109.70.100.7 malicious?
```

## Verification Checklist

- [ ] MCP server added to settings.json
- [ ] VS Code restarted
- [ ] Copilot chat opened (@workspace chat)
- [ ] Test command executed
- [ ] Text summary received
- [ ] Interactive UI rendered (if MCP Apps enabled in your VS Code)

## Troubleshooting

### Server Not Found
- Check settings.json has correct path to `dist/index.js`
- Verify Node.js is in PATH: `node --version`
- Check CYBERPROBE_ROOT points to correct directory

### Python Script Errors
- Ensure .venv exists at CYBERPROBE_ROOT
- Check Python path in `src/tools/analyze-ips.ts` line 75
- Verify `requests` package installed: `.\setup-environment.ps1`

### No Interactive UI
- Confirm VS Code version 1.108+ (you have 1.108.2 ✓)
- Check browser console in UI panel for errors
- Verify HTML resource is returned (check Output → MCP Server logs)

## Architecture Flow

1. **User asks Copilot** → "Analyze IPs: 109.70.100.7, 176.65.134.8"
2. **VS Code calls tool** → `analyze_ip_threats` via MCP protocol
3. **MCP Server runs** → Node.js spawns Python enrichment script
4. **Python enriches** → Calls AbuseIPDB, IPInfo, VPNapi APIs
5. **Server returns** → Text summary + metadata with `ui/resourceUri`
6. **VS Code fetches** → HTML resource from `ui://cyberprobe/threat-map`
7. **UI renders** → Interactive table with threat data in iframe

## Current Status

✅ MCP Apps server built successfully (`npm run build` completed)
✅ TypeScript compiled without errors
✅ VS Code version compatible (1.108.2)
⏳ Waiting for: settings.json configuration
⏳ Waiting for: VS Code restart
⏳ Waiting for: First test in Copilot

## Quick Config Check

Run this to verify your paths are correct:

```powershell
# Check MCP server exists
Test-Path "<path-to-repo>/cyberprobe-mcp-apps/dist/index.js"

# Check Python venv exists
Test-Path "<path-to-repo>/.venv/Scripts/python.exe"

# Check enrichment script exists
Test-Path "<path-to-repo>/enrichment/enrich_ips.py"
```

All should return `True`.
