#!/usr/bin/env node

/**
 * CyberProbe MCP Apps Server v2.0
 * 
 * Provides interactive security investigation tools for VS Code Copilot
 * using the MCP Apps extension for inline UI rendering.
 * 
 * Architecture:
 * - Tool + UI Resource pattern: Tool declares a ui:// resource
 * - When host calls the tool, it fetches the resource and renders inline
 * - UI receives tool result data via MCP Apps bridge
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  registerAppResource,
  registerAppTool,
  RESOURCE_MIME_TYPE,
} from '@modelcontextprotocol/ext-apps/server';
import { analyzeIPThreats } from './tools/analyze-ips.js';
import {
  Entity,
  ipToEntity,
  userToEntity,
  deviceToEntity,
  alertToEntity,
  iocToEntity,
  generateSummary,
  generateEntityExplorerHTML,
} from './tools/entity-explorer.js';
import {
  PostureData,
  generateSummary as generatePostureSummary,
  generatePostureReportHTML,
} from './tools/security-posture.js';
import {
  ResponseData,
  ResponseAction,
  computeSummary as computeResponseSummary,
  generateSummary as generateResponseSummary,
  generateResponseActionsHTML,
} from './tools/response-actions.js';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { exec } from 'child_process';

const DIST_DIR = path.join(import.meta.dirname, '.');

/**
 * Creates and configures the MCP server with tools and UI resources
 */
function createServer(): McpServer {
  const server = new McpServer({
    name: 'cyberprobe-mcp-apps',
    version: '2.0.0',
  });

  // Resource URI for the threat map UI
  const THREAT_MAP_URI = 'ui://cyberprobe/threat-map';
  const ENTITY_EXPLORER_URI = 'ui://cyberprobe/entity-explorer';
  const SECURITY_POSTURE_URI = 'ui://cyberprobe/security-posture';
  const RESPONSE_ACTIONS_URI = 'ui://cyberprobe/response-actions';

  // Register the analyze_ip_threats tool with UI metadata
  registerAppTool(
    server,
    'analyze_ip_threats',
    {
      description:
        'Analyze IP addresses for threat intelligence using AbuseIPDB, IPInfo, and VPNapi. ' +
        'Displays an interactive geographic map with color-coded threat severity. ' +
        'Use when investigating suspicious IPs from security incidents.',
      inputSchema: {
        ips: z.array(z.string().regex(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/))
          .min(1)
          .max(50)
          .describe('Array of IPv4 addresses to analyze (e.g., ["109.70.100.7", "176.65.134.8"])'),
      },
      _meta: {
        ui: {
          resourceUri: THREAT_MAP_URI,
        },
      },
    },
    async (args: { ips: string[] }) => {
      if (!args || !Array.isArray(args.ips)) {
        throw new Error('Invalid arguments: ips array is required');
      }

      const result = await analyzeIPThreats(args.ips);

      // Return tool result - the enrichmentData will be passed to the UI
      return {
        content: [
          {
            type: 'text',
            text: result.summary,
          },
        ],
        // This data is forwarded to the UI via MCP Apps bridge
        _meta: {
          enrichmentData: result.enrichmentData.ips,
        },
      };
    }
  );

  // Register the UI resource that renders the threat map
  registerAppResource(
    server,
    'IP Threat Map',
    THREAT_MAP_URI,
    {
      description: 'Interactive geographic visualization for IP threat analysis',
    },
    async () => {
      // Read the bundled HTML file
      const htmlPath = path.join(DIST_DIR, 'mcp-app.html');
      
      try {
        const html = await fs.readFile(htmlPath, 'utf-8');
        return {
          contents: [
            {
              uri: THREAT_MAP_URI,
              mimeType: RESOURCE_MIME_TYPE,
              text: html,
              // CSP configuration to allow Leaflet map tiles and CDN resources
              _meta: {
                ui: {
                  csp: {
                    // Allow Leaflet CDN and CARTO map tiles
                    resourceDomains: [
                      'https://unpkg.com',
                      'https://*.basemaps.cartocdn.com',
                    ],
                    // Allow tile server connections
                    connectDomains: [
                      'https://*.basemaps.cartocdn.com',
                    ],
                  },
                },
              },
            },
          ],
        };
      } catch (error) {
        // Fallback: return a simple error message if HTML not found
        console.error('Failed to load mcp-app.html:', error);
        return {
          contents: [
            {
              uri: THREAT_MAP_URI,
              mimeType: RESOURCE_MIME_TYPE,
              text: `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body style="background:#0d1117;color:#f85149;font-family:system-ui;padding:20px;">
  <h2>UI Resource Not Found</h2>
  <p>The threat map UI was not built. Run <code>npm run build</code> in cyberprobe-mcp-apps.</p>
</body>
</html>`,
            },
          ],
        };
      }
    }
  );

  // ============================================================
  // ENTITY EXPLORER - Interactive list of IPs, Users, Devices
  // ============================================================
  
  // Entity schema for validation
  const EntitySchema = z.object({
    type: z.enum(['ip', 'user', 'device', 'domain', 'email', 'file', 'hash', 'url', 'process', 'alert']),
    value: z.string(),
    name: z.string().optional(),
    description: z.string().optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    tags: z.array(z.string()).optional(),
    details: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
  });

  // Register the explore_entities tool
  registerAppTool(
    server,
    'explore_entities',
    {
      description:
        'Display an interactive list of security entities (IPs, users, devices, alerts, IOCs). ' +
        'Supports filtering, searching, and drill-down details. ' +
        'Use after gathering investigation data to present findings interactively.',
      inputSchema: {
        entities: z.array(z.any())
          .min(1)
          .describe('Array of entity objects with type, value, name, severity, tags, and details'),
        title: z.string()
          .optional()
          .describe('Optional title for the entity list'),
      },
      _meta: {
        ui: {
          resourceUri: ENTITY_EXPLORER_URI,
        },
      },
    },
    async (args: { entities: any[]; title?: string }) => {
      if (!args || !Array.isArray(args.entities)) {
        throw new Error('Invalid arguments: entities array is required');
      }

      // Convert raw data to Entity format based on detected type
      const entities: Entity[] = args.entities.map(item => {
        // If already in Entity format, use as-is
        if (item.type && item.value) {
          return item as Entity;
        }
        
        // Auto-detect and convert based on properties
        if (item.ip || item.abuse_confidence_score !== undefined) {
          return ipToEntity(item);
        }
        if (item.userPrincipalName || item.upn || item.displayName) {
          return userToEntity(item);
        }
        if (item.computerDnsName || item.deviceId || item.osPlatform) {
          return deviceToEntity(item);
        }
        if (item.alertId || item.mitreTactics) {
          return alertToEntity(item);
        }
        
        // Fallback to IOC detection
        return iocToEntity(item);
      });

      // Generate standalone HTML and save it
      const cyberprobeRoot = process.env.CYBERPROBE_ROOT || path.resolve(DIST_DIR, '../../');
      const timestamp = new Date().toISOString().slice(0, 10);
      const htmlFilename = `entity_explorer_${timestamp}.html`;
      const htmlPath = path.join(cyberprobeRoot, 'reports', htmlFilename);
      
      const htmlContent = generateEntityExplorerHTML(entities, args.title);
      fsSync.writeFileSync(htmlPath, htmlContent, 'utf-8');
      
      // Auto-open in browser
      const openCommand = process.platform === 'win32' ? 'start' : process.platform === 'darwin' ? 'open' : 'xdg-open';
      exec(`${openCommand} "${htmlPath}"`);

      const summary = generateSummary(entities);

      return {
        content: [
          {
            type: 'text',
            text: summary + `\n\n📂 **Interactive explorer opened** → [${htmlFilename}](reports/${htmlFilename})`,
          },
        ],
        _meta: {
          entities,
          title: args.title,
        },
      };
    }
  );

  // Register Entity Explorer UI resource
  registerAppResource(
    server,
    'Entity Explorer',
    ENTITY_EXPLORER_URI,
    {
      description: 'Interactive entity list for security investigations',
    },
    async () => {
      const htmlPath = path.join(DIST_DIR, 'entity-explorer.html');
      
      try {
        const html = await fs.readFile(htmlPath, 'utf-8');
        return {
          contents: [
            {
              uri: ENTITY_EXPLORER_URI,
              mimeType: RESOURCE_MIME_TYPE,
              text: html,
            },
          ],
        };
      } catch (error) {
        console.error('Failed to load entity-explorer.html:', error);
        return {
          contents: [
            {
              uri: ENTITY_EXPLORER_URI,
              mimeType: RESOURCE_MIME_TYPE,
              text: `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body style="background:#0d1117;color:#f85149;font-family:system-ui;padding:20px;">
  <h2>UI Resource Not Found</h2>
  <p>The entity explorer UI was not built. Run <code>npm run build</code> in cyberprobe-mcp-apps.</p>
</body>
</html>`,
            },
          ],
        };
      }
    }
  );

  // ============================================================
  // SECURITY POSTURE DASHBOARD
  // ============================================================

  registerAppTool(
    server,
    'security_posture_dashboard',
    {
      description:
        'Display an interactive security posture dashboard for Defender for Servers. ' +
        'Shows VM inventory, cost analysis, AV compliance, exposure analysis, attack paths, ' +
        'CSPM findings, blind spots, MITRE ATT&CK mapping, and prioritized recommendations. ' +
        'Use after gathering posture data from Azure Resource Graph, Defender for Endpoint, ' +
        'and Defender for Cloud.',
      inputSchema: {
        title: z.string().optional().describe('Dashboard title'),
        reportDate: z.string().optional().describe('Report date (YYYY-MM-DD)'),
        vmInventory: z.object({
          total: z.number(), running: z.number(), deallocated: z.number(),
          subscriptions: z.array(z.object({ name: z.string(), running: z.number(), deallocated: z.number(), total: z.number() })),
        }),
        costs: z.object({
          monthlyP2: z.number(), annualP2: z.number(), monthlyCompute: z.number(), securityRatio: z.number(),
        }),
        avCompliance: z.object({
          current: z.number(), slightlyOutdated: z.number(), outdated: z.number(), criticallyOutdated: z.number(),
          latestSignature: z.string(),
          devices: z.array(z.object({
            name: z.string(), os: z.string(), signature: z.string(), daysBehind: z.number(),
            exposure: z.string(), sensor: z.string(), chokePoint: z.string().optional(), tags: z.array(z.string()).optional(),
          })),
        }),
        exposure: z.object({
          devices: z.array(z.object({
            name: z.string(), os: z.string(), sensor: z.string(),
            critVulns: z.number(), highVulns: z.number(), totalVulns: z.number(),
            alerts30d: z.number(), avAge: z.string(), chokePoint: z.string().optional(),
          })),
        }),
        attackPaths: z.object({
          critical: z.number(), high: z.number(), medium: z.number(), low: z.number(), total: z.number(),
          chokePoints: z.array(z.object({
            name: z.string(), type: z.string(), pathsBlocked: z.number(),
            priority: z.string(), details: z.string().optional(),
          })),
        }),
        cspm: z.object({ high: z.number(), medium: z.number(), low: z.number(), total: z.number() }),
        blindSpots: z.array(z.object({
          name: z.string(), os: z.string(), lastSeen: z.string(), avSignature: z.string(), daysOffline: z.number(),
        })),
        mitre: z.array(z.object({
          id: z.string(), name: z.string(), evidence: z.string(),
          affected: z.string().optional(), tactic: z.string().optional(),
        })),
        recommendations: z.array(z.object({ priority: z.string(), title: z.string(), description: z.string() })),
      },
      _meta: {
        ui: {
          resourceUri: SECURITY_POSTURE_URI,
        },
      },
    },
    async (args: PostureData) => {
      // Generate standalone HTML report
      const cyberprobeRoot = process.env.CYBERPROBE_ROOT || path.resolve(DIST_DIR, '../../');
      const timestamp = args.reportDate || new Date().toISOString().slice(0, 10);
      const htmlFilename = `security_posture_${timestamp}.html`;
      const htmlPath = path.join(cyberprobeRoot, 'reports', htmlFilename);

      const htmlContent = generatePostureReportHTML(args);
      fsSync.writeFileSync(htmlPath, htmlContent, 'utf-8');

      // Auto-open in browser
      const openCommand = process.platform === 'win32' ? 'start' : process.platform === 'darwin' ? 'open' : 'xdg-open';
      exec(`${openCommand} "${htmlPath}"`);

      const summary = generatePostureSummary(args);

      return {
        content: [
          {
            type: 'text',
            text: summary + `\n\n📂 **Interactive dashboard opened** → [${htmlFilename}](reports/${htmlFilename})`,
          },
        ],
        _meta: {
          postureData: args,
          reportPath: `file:///${htmlPath.replace(/\\/g, '/')}`,
        },
      };
    }
  );

  // Register Security Posture Dashboard UI resource
  registerAppResource(
    server,
    'Security Posture Dashboard',
    SECURITY_POSTURE_URI,
    {
      description: 'Interactive security posture dashboard for Defender for Servers',
    },
    async () => {
      const htmlPath = path.join(DIST_DIR, 'security-posture.html');

      try {
        const html = await fs.readFile(htmlPath, 'utf-8');
        return {
          contents: [
            {
              uri: SECURITY_POSTURE_URI,
              mimeType: RESOURCE_MIME_TYPE,
              text: html,
            },
          ],
        };
      } catch (error) {
        console.error('Failed to load security-posture.html:', error);
        return {
          contents: [
            {
              uri: SECURITY_POSTURE_URI,
              mimeType: RESOURCE_MIME_TYPE,
              text: `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body style="background:#0d1117;color:#f85149;font-family:system-ui;padding:20px;">
  <h2>UI Resource Not Found</h2>
  <p>Run <code>npm run build</code> in cyberprobe-mcp-apps.</p>
</body>
</html>`,
            },
          ],
        };
      }
    }
  );

  // ============================================================
  // RESPONSE ACTIONS CONSOLE
  // ============================================================

  const ResponseActionSchema = z.object({
    id: z.string().optional(),
    type: z.enum(['device', 'identity', 'incident', 'forensic']),
    action: z.string(),
    target: z.string(),
    status: z.enum(['Succeeded', 'Pending', 'InProgress', 'Failed', 'Cancelled', 'planned']),
    timestamp: z.string().optional(),
    requestor: z.string().optional(),
    comment: z.string().optional(),
    details: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
  });

  const PlaybookStepSchema = z.object({
    action: z.string(),
    tool: z.string(),
    status: z.string().optional(),
  });

  const PlaybookSchema = z.object({
    name: z.string(),
    icon: z.string(),
    trigger: z.string(),
    steps: z.array(PlaybookStepSchema),
  });

  registerAppTool(
    server,
    'response_actions_console',
    {
      description:
        'Display an interactive Response Actions Console for Defender incident response. ' +
        'Shows device isolation, identity containment, incident management, forensic collections, ' +
        'response playbooks, and full action history with search/filter. ' +
        'Use after performing response actions to visualize and track containment progress.',
      inputSchema: {
        title: z.string().optional().describe('Console title'),
        reportDate: z.string().optional().describe('Report date (YYYY-MM-DD)'),
        actions: z.array(ResponseActionSchema)
          .min(1)
          .describe('Array of response actions with type, action, target, status, timestamp, and optional details'),
        playbooks: z.array(PlaybookSchema).optional()
          .describe('Optional playbook definitions with steps and MCP tool names'),
      },
      _meta: {
        ui: {
          resourceUri: RESPONSE_ACTIONS_URI,
        },
      },
    },
    async (args: ResponseData) => {
      // Generate standalone HTML report
      const cyberprobeRoot = process.env.CYBERPROBE_ROOT || path.resolve(DIST_DIR, '../../');
      const timestamp = args.reportDate || new Date().toISOString().slice(0, 10);
      const htmlFilename = `response_actions_${timestamp}.html`;
      const htmlPath = path.join(cyberprobeRoot, 'reports', htmlFilename);

      const htmlContent = generateResponseActionsHTML(args);
      fsSync.writeFileSync(htmlPath, htmlContent, 'utf-8');

      // Auto-open in browser
      const openCommand = process.platform === 'win32' ? 'start' : process.platform === 'darwin' ? 'open' : 'xdg-open';
      exec(`${openCommand} "${htmlPath}"`);

      const summary = generateResponseSummary(args);

      return {
        content: [
          {
            type: 'text',
            text: summary + `\n\n📂 **Interactive console opened** → [${htmlFilename}](reports/${htmlFilename})`,
          },
        ],
        _meta: {
          responseData: args,
          reportPath: `file:///${htmlPath.replace(/\\/g, '/')}`,
        },
      };
    }
  );

  // Register Response Actions Console UI resource
  registerAppResource(
    server,
    'Response Actions Console',
    RESPONSE_ACTIONS_URI,
    {
      description: 'Interactive response actions console for Defender incident response',
    },
    async () => {
      const htmlPath = path.join(DIST_DIR, 'response-actions.html');

      try {
        const html = await fs.readFile(htmlPath, 'utf-8');
        return {
          contents: [
            {
              uri: RESPONSE_ACTIONS_URI,
              mimeType: RESOURCE_MIME_TYPE,
              text: html,
            },
          ],
        };
      } catch (error) {
        console.error('Failed to load response-actions.html:', error);
        return {
          contents: [
            {
              uri: RESPONSE_ACTIONS_URI,
              mimeType: RESOURCE_MIME_TYPE,
              text: `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body style="background:#0d1117;color:#f85149;font-family:system-ui;padding:20px;">
  <h2>UI Resource Not Found</h2>
  <p>Run <code>npm run build</code> in cyberprobe-mcp-apps.</p>
</body>
</html>`,
            },
          ],
        };
      }
    }
  );

  return server;
}

/**
 * Start the MCP server
 */
async function main() {
  const server = createServer();
  const transport = new StdioServerTransport();
  
  await server.connect(transport);

  // Log to stderr (stdout is used for MCP protocol)
  console.error('CyberProbe MCP Apps Server v2.0 running');
  console.error('Available tools: analyze_ip_threats, explore_entities, security_posture_dashboard, response_actions_console');
  console.error('UI Resources: ui://cyberprobe/threat-map, ui://cyberprobe/entity-explorer, ui://cyberprobe/security-posture, ui://cyberprobe/response-actions');
}

main().catch((error) => {
  console.error('Server error:', error);
  process.exit(1);
});
