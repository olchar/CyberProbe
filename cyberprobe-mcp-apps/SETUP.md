# CyberProbe MCP Apps - Setup Guide

## Step 1: Install Node.js
Download and install Node.js 18+ from https://nodejs.org/

Verify installation:
```powershell
node --version  # Should show v18 or higher
npm --version
```

## Step 2: Install Dependencies
```powershell
cd "<path-to-repo>/cyberprobe-mcp-apps"
npm install
```

## Step 3: Build the Project
```powershell
npm run build
```

You should see:
```
Compiled successfully
MCP App manifests copied successfully
```

## Step 4: Configure VS Code

### Option A: User Settings (Recommended)
1. Open VS Code
2. Press `Ctrl+Shift+P` → "Preferences: Open User Settings (JSON)"
3. Add this configuration:

```json
{
  "mcp.servers": {
    "cyberprobe": {
      "command": "node",
      "args": [
        "<path-to-repo>/cyberprobe-mcp-apps/dist/index.js"
      ],
      "env": {
        "CYBERPROBE_ROOT": "<path-to-repo>"
      }
    }
  }
}
```

### Option B: Workspace Settings
1. In your CyberProbe workspace, create `.vscode/settings.json`:

```json
{
  "mcp.servers": {
    "cyberprobe": {
      "command": "node",
      "args": [
        "${workspaceFolder}/cyberprobe-mcp-apps/dist/index.js"
      ],
      "env": {
        "CYBERPROBE_ROOT": "${workspaceFolder}"
      }
    }
  }
}
```

## Step 5: Install VS Code Insiders (if needed)

MCP Apps is available in:
- **VS Code Insiders** (available now) - https://code.visualstudio.com/insiders/
- **VS Code Stable 1.108+** (released in next update)

## Step 6: Restart VS Code

After configuration, restart VS Code completely:
1. Close all VS Code windows
2. Reopen your workspace
3. Wait for MCP server to initialize (check status bar)

## Step 7: Verify Installation

Open GitHub Copilot Chat and try:

```
Analyze these IPs: 109.70.100.7, 176.65.134.8, 76.182.132.142
```

You should see:
1. Text summary with abuse scores
2. **Interactive map** with geographic markers
3. Color-coded severity (red = critical, orange = high, etc.)
4. Clickable markers for detailed info

## Troubleshooting

### MCP Server Not Starting
1. Check VS Code Output panel → "MCP Servers"
2. Look for errors in server logs
3. Verify Node.js path: `where node`

### Python Script Fails
1. Ensure Python virtual environment is activated
2. Check enrichment config: `../enrichment/config.json`
3. Verify API keys are configured

### No Interactive Map Shown
1. Confirm you're using VS Code Insiders or Stable 1.108+
2. Check that MCP Apps is enabled in Copilot settings
3. Look for `application/vnd.mcp.app+json` in response

### Debug Mode
Run the server manually to see detailed logs:
```powershell
node "<path-to-repo>/cyberprobe-mcp-apps/dist/index.js"
```

## Next Steps

Once working, try these queries:

```
Show me a threat map for incident 42281 IPs

Analyze these high-risk IPs and show me which ones to block: 
109.70.100.7, 176.65.134.8, 193.189.100, 4.194.122

Create an interactive map of all IPs from the last security alert
```

## Development Workflow

### Make Changes
1. Edit files in `src/`
2. Run `npm run build`
3. Restart VS Code MCP server (or reload window)

### Watch Mode
```powershell
npm run dev  # Auto-rebuild on changes
```

### Test with Inspector
```powershell
npm install -g @modelcontextprotocol/inspector
npm run inspector
```

## Support

- MCP Apps Docs: https://modelcontextprotocol.github.io/ext-apps/
- VS Code MCP Docs: https://code.visualstudio.com/docs/copilot/customization/mcp-servers
- CyberProbe Issues: https://github.com/your-repo/issues
