hat # MCP Apps Implementation Guide

## Fixed Implementation

The original implementation incorrectly tried to use an `AppManifest` export that doesn't exist in the `@modelcontextprotocol/ext-apps` package. The correct approach follows the MCP Apps specification:

### How MCP Apps Actually Work

1. **MCP Server** declares and serves HTML resources (not app manifests)
2. **Tool results** include metadata pointing to UI resources via `ui/resourceUri`
3. **Host** fetches the HTML resource and renders it in an iframe
4. **HTML/App** uses the App SDK to receive data and communicate with the host

### Architecture

```
┌─────────────────┐
│   VS Code Host  │
│   (Copilot)     │
└────────┬────────┘
         │
         │ MCP Protocol (stdio)
         │
┌────────▼────────────────────────────┐
│  MCP Server (Node.js/TypeScript)    │
│  ├─ Tools (analyze_ip_threats)      │
│  ├─ Resources (ui://threat-map)     │
│  └─ Returns: metadata with URI      │
└─────────────────────────────────────┘
         │
         │ Fetch Resource
         │
┌────────▼────────────────────────────┐
│  HTML UI (in iframe)                │
│  ├─ Uses @modelcontextprotocol/     │
│  │   ext-apps SDK                   │
│  └─ Renders data from metadata      │
└─────────────────────────────────────┘
```

### Key Changes Made

#### 1. Server Capabilities
**Before:**
```typescript
capabilities: {
  tools: {},
  apps: {}, // ❌ This doesn't exist
}
```

**After:**
```typescript
capabilities: {
  tools: {},
  resources: {}, // ✅ Correct
}
```

#### 2. Resource Handlers
**Added:**
- `ListResourcesRequestSchema` handler to list available UI resources
- `ReadResourceRequestSchema` handler to serve HTML content

```typescript
server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return {
    resources: [{
      uri: 'ui://cyberprobe/threat-map',
      name: 'IP Threat Map',
      description: 'Interactive map visualization',
      mimeType: 'text/html;profile=mcp-app',
    }],
  };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  if (request.params.uri === 'ui://cyberprobe/threat-map') {
    const html = generateThreatMapHTML();
    return {
      contents: [{
        uri: request.params.uri,
        mimeType: 'text/html;profile=mcp-app',
        text: html,
      }],
    };
  }
  throw new Error(`Unknown resource: ${uri}`);
});
```

#### 3. Tool Results
**Before:**
```typescript
return {
  content: [{
    type: 'resource',
    resource: {
      uri: 'mcp://...',
      mimeType: 'application/vnd.mcp.app+json',
      text: JSON.stringify(appData),
    },
  }],
};
```

**After:**
```typescript
return {
  content: [{
    type: 'text',
    text: result.summary, // Text for LLM/chat
  }],
  _meta: {
    'ui/resourceUri': 'ui://cyberprobe/threat-map', // Points to HTML resource
    enrichmentData: result.enrichmentData, // Data passed to UI
  },
};
```

#### 4. HTML/App Implementation
**Removed:** `src/apps/ip-threat-map.ts` (AppManifest doesn't exist)

**Added:** HTML generation in `src/tools/analyze-ips.ts`:

```typescript
export function generateThreatMapHTML(): string {
  return `<!DOCTYPE html>
<html>
<head>
  <title>IP Threat Map</title>
  <style>/* Dark theme styles */</style>
</head>
<body>
  <div id="app">Loading...</div>
  
  <script type="module">
    import { App } from '@modelcontextprotocol/ext-apps';
    
    const app = new App({
      name: 'CyberProbe IP Threat Map',
      version: '1.0.0',
    }, {
      capabilities: {}
    });
    
    // Receive tool result data
    app.ontoolresult = (notification) => {
      const data = notification.params.result._meta?.enrichmentData;
      render(data);
    };
    
    await app.connect();
  </script>
</body>
</html>`;
}
```

### Data Flow

1. **User asks Copilot:** "Analyze IPs: 109.70.100.7, 176.65.134.8"
2. **Copilot calls tool:** `analyze_ip_threats` with IPs
3. **Server enriches IPs:** Calls Python script, gets threat data
4. **Server returns:** Text summary + metadata with `ui/resourceUri` and `enrichmentData`
5. **Host fetches resource:** Reads `ui://cyberprobe/threat-map` HTML
6. **Host renders HTML:** Displays in iframe sandbox
7. **HTML receives data:** Via `ontoolresult` notification with enrichmentData
8. **UI renders:** Interactive table with statistics

### Testing

1. **Build:** `npm run build`
2. **Configure VS Code:** Add to `settings.json`:
   ```json
   {
     "mcp.servers": {
       "cyberprobe": {
         "command": "node",
         "args": ["C:/Users/.../cyberprobe-mcp-apps/dist/index.js"],
         "env": {
           "CYBERPROBE_ROOT": "C:/Users/.../CyberProbe"
         }
       }
     }
   }
   ```
3. **Use in Copilot:** "Analyze these IPs: 109.70.100.7, 176.65.134.8"

### References

- [MCP Apps Specification](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- [ext-apps Package](https://www.npmjs.com/package/@modelcontextprotocol/ext-apps)
- [VS Code MCP Apps Blog](https://code.visualstudio.com/blogs/2026/01/26/mcp-apps-support)

## Build Success

✅ TypeScript compilation successful  
✅ No `AppManifest` import errors  
✅ Proper resource-based architecture  
✅ HTML UI with App SDK integration
