/**
 * IP Threat Analysis Tool
 * 
 * Integrates with CyberProbe's Python enrichment pipeline to analyze
 * IP addresses and generate interactive visualizations.
 */

import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'node:fs';
import { exec } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Generate a standalone HTML map file that works in any browser
 */
function generateStandaloneMapHTML(enrichedData: IPEnrichmentResult[], markers: any[]): string {
  const validMarkers = markers.filter(m => m.lat !== 0 || m.lng !== 0);
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Threat Map - CyberProbe</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
        .container { display: flex; height: 100vh; }
        #map { flex: 1; }
        .sidebar { width: 320px; background: #1a1a2e; color: #eee; overflow-y: auto; padding: 16px; }
        .sidebar h1 { font-size: 18px; margin-bottom: 16px; color: #fff; }
        .stats { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 16px; }
        .stat { background: #16213e; padding: 12px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; }
        .stat-label { font-size: 11px; color: #888; text-transform: uppercase; }
        .critical .stat-value { color: #f85149; }
        .high .stat-value { color: #d29922; }
        .medium .stat-value { color: #e3b341; }
        .clean .stat-value { color: #3fb950; }
        .ip-list { margin-top: 16px; }
        .ip-list h2 { font-size: 12px; color: #888; margin-bottom: 8px; text-transform: uppercase; }
        .ip-card { background: #16213e; border-radius: 8px; padding: 12px; margin-bottom: 8px; cursor: pointer; border-left: 3px solid #3fb950; }
        .ip-card.critical { border-left-color: #f85149; }
        .ip-card.high { border-left-color: #d29922; }
        .ip-card.medium { border-left-color: #e3b341; }
        .ip-card:hover { background: #1f2847; }
        .ip-card h3 { font-size: 14px; color: #fff; margin-bottom: 4px; }
        .ip-card p { font-size: 12px; color: #888; margin: 2px 0; }
        .ip-card .score { font-weight: bold; }
        .ip-card .flags { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 6px; }
        .ip-card .flag { background: #0d1b2a; padding: 2px 6px; border-radius: 4px; font-size: 10px; }
        .leaflet-popup-content-wrapper { background: #1a1a2e; color: #eee; border-radius: 8px; }
        .leaflet-popup-tip { background: #1a1a2e; }
        .popup-content h3 { margin-bottom: 8px; color: #fff; }
        .popup-content p { margin: 4px 0; font-size: 13px; }
        .popup-content .label { color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div id="map"></div>
        <div class="sidebar">
            <h1>🌐 IP Threat Analysis</h1>
            <div class="stats">
                <div class="stat critical">
                    <div class="stat-value">${enrichedData.filter(ip => ip.abuse_confidence_score >= 90).length}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat high">
                    <div class="stat-value">${enrichedData.filter(ip => ip.abuse_confidence_score >= 75 && ip.abuse_confidence_score < 90).length}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat medium">
                    <div class="stat-value">${enrichedData.filter(ip => ip.abuse_confidence_score >= 25 && ip.abuse_confidence_score < 75).length}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat clean">
                    <div class="stat-value">${enrichedData.filter(ip => ip.abuse_confidence_score < 25).length}</div>
                    <div class="stat-label">Clean</div>
                </div>
            </div>
            <div class="ip-list">
                <h2>Analyzed IPs</h2>
                ${markers.map(m => `
                <div class="ip-card ${m.severity}" onclick="flyTo(${m.lat}, ${m.lng}, '${m.ip}')">
                    <h3>${m.ip}</h3>
                    <p>${m.city}, ${m.country}</p>
                    <p>Abuse Score: <span class="score" style="color: ${m.severity === 'critical' ? '#f85149' : m.severity === 'high' ? '#d29922' : m.severity === 'medium' ? '#e3b341' : '#3fb950'}">${m.abuseScore}%</span></p>
                    <p>${m.org}</p>
                    ${m.flags.length > 0 ? `<div class="flags">${m.flags.map((f: string) => `<span class="flag">${f}</span>`).join('')}</div>` : ''}
                </div>
                `).join('')}
            </div>
        </div>
    </div>
    <script>
        const markers = ${JSON.stringify(validMarkers)};
        const markerObjects = {};
        
        const map = L.map('map').setView([${validMarkers.length > 0 ? validMarkers[0].lat : 48}, ${validMarkers.length > 0 ? validMarkers[0].lng : 14}], 4);
        
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors'
        }).addTo(map);
        
        const severityColors = {
            critical: '#f85149',
            high: '#d29922',
            medium: '#e3b341',
            clean: '#3fb950'
        };
        
        markers.forEach((m, i) => {
            const color = severityColors[m.severity];
            const icon = L.divIcon({
                className: 'custom-marker',
                html: \`<div style="width: 24px; height: 24px; background: \${color}; border: 3px solid white; border-radius: 50%; box-shadow: 0 2px 6px rgba(0,0,0,0.4);"></div>\`,
                iconSize: [24, 24],
                iconAnchor: [12, 12]
            });
            
            const marker = L.marker([m.lat + (i * 0.01), m.lng + (i * 0.01)], { icon }).addTo(map);
            markerObjects[m.ip] = marker;
            
            const popup = \`
                <div class="popup-content">
                    <h3>\${m.ip}</h3>
                    <p><span class="label">Location:</span> \${m.city}, \${m.country}</p>
                    <p><span class="label">Organization:</span> \${m.org}</p>
                    <p><span class="label">Abuse Score:</span> <strong style="color: \${color}">\${m.abuseScore}%</strong></p>
                    \${m.flags.length > 0 ? '<p><span class="label">Flags:</span> ' + m.flags.join(', ') + '</p>' : ''}
                </div>
            \`;
            marker.bindPopup(popup);
        });
        
        if (markers.length > 0) {
            const bounds = markers.map(m => [m.lat, m.lng]);
            map.fitBounds(bounds, { padding: [50, 50] });
        }
        
        function flyTo(lat, lng, ip) {
            map.flyTo([lat, lng], 8);
            if (markerObjects[ip]) {
                markerObjects[ip].openPopup();
            }
        }
    <\/script>
</body>
</html>`;
}

interface IPEnrichmentResult {
  ip: string;
  city: string;
  region: string;
  country: string;
  org: string;
  asn: string;
  timezone: string;
  is_vpn: boolean;
  is_proxy: boolean;
  is_tor: boolean;
  is_hosting: boolean;
  vpnapi_security_vpn: boolean;
  vpnapi_security_proxy: boolean;
  vpnapi_security_tor: boolean;
  vpnapi_security_relay: boolean;
  abuse_confidence_score: number;
  total_reports: number;
  is_whitelisted: boolean;
}

interface AnalysisResult {
  summary: string;
  enrichmentData: {
    ips: IPEnrichmentResult[];
    statistics: {
      total: number;
      critical: number;
      high: number;
      medium: number;
      clean: number;
      vpnDetected: number;
    };
    markers: Array<{
      lat: number;
      lng: number;
      ip: string;
      severity: 'critical' | 'high' | 'medium' | 'clean';
      abuseScore: number;
      city: string;
      country: string;
      org: string;
      flags: string[];
    }>;
  };
}

/**
 * Call CyberProbe's Python enrichment script
 */
async function enrichIPs(ips: string[]): Promise<IPEnrichmentResult[]> {
  const cyberprobeRoot = process.env.CYBERPROBE_ROOT || path.resolve(__dirname, '../../../');
  const pythonScript = path.join(cyberprobeRoot, 'enrichment', 'enrich_ips.py');
  const pythonExecutable = path.join(cyberprobeRoot, '.venv', 'Scripts', 'python.exe');

  return new Promise((resolve, reject) => {
    const python = spawn(pythonExecutable, [pythonScript, ...ips], {
      cwd: path.join(cyberprobeRoot, 'enrichment'),
    });

    let stdout = '';
    let stderr = '';

    python.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    python.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    python.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Python script failed: ${stderr}`));
        return;
      }

      // Parse the JSON output from the enrichment script
      try {
        // Find the most recent JSON file
        const reportsDir = path.join(cyberprobeRoot, 'enrichment', 'reports');
        const files = fs.readdirSync(reportsDir)
          .filter((f: string) => f.startsWith('ip_enrichment_') && f.endsWith('.json'))
          .map((f: string) => ({
            name: f,
            time: fs.statSync(path.join(reportsDir, f)).mtime.getTime(),
          }))
          .sort((a: any, b: any) => b.time - a.time);

        if (files.length === 0) {
          reject(new Error('No enrichment results found'));
          return;
        }

        const latestFile = path.join(reportsDir, files[0].name);
        const data = JSON.parse(fs.readFileSync(latestFile, 'utf-8'));
        resolve(data);
      } catch (error) {
        reject(new Error(`Failed to parse enrichment results: ${error}`));
      }
    });
  });
}

/**
 * Generate latitude/longitude from country code (simplified)
 * In production, you'd use a proper geocoding service
 */
function getCoordinates(country: string, city: string): { lat: number; lng: number } {
  // Simplified mapping - in production use real geocoding
  const countryCoords: Record<string, { lat: number; lng: number }> = {
    'AT': { lat: 48.2082, lng: 16.3738 }, // Austria (Vienna)
    'SI': { lat: 46.0569, lng: 14.5058 }, // Slovenia (Ljubljana)
    'US': { lat: 39.8283, lng: -98.5795 }, // United States
    'GB': { lat: 51.5074, lng: -0.1278 }, // United Kingdom
    'Unknown': { lat: 0, lng: 0 },
  };

  return countryCoords[country] || { lat: 0, lng: 0 };
}

/**
 * Determine severity level based on abuse score
 */
function getSeverity(abuseScore: number, isVpn: boolean): 'critical' | 'high' | 'medium' | 'clean' {
  if (abuseScore >= 90) return 'critical';
  if (abuseScore >= 75) return 'high';
  if (abuseScore >= 25 || isVpn) return 'medium';
  return 'clean';
}

/**
 * Analyze IP threats and generate MCP App data
 */
export async function analyzeIPThreats(ips: string[]): Promise<AnalysisResult> {
  // Call the Python enrichment script
  const enrichedData = await enrichIPs(ips);

  // Calculate statistics
  const statistics = {
    total: enrichedData.length,
    critical: enrichedData.filter(ip => ip.abuse_confidence_score >= 90).length,
    high: enrichedData.filter(ip => ip.abuse_confidence_score >= 75 && ip.abuse_confidence_score < 90).length,
    medium: enrichedData.filter(ip => ip.abuse_confidence_score >= 25 && ip.abuse_confidence_score < 75).length,
    clean: enrichedData.filter(ip => ip.abuse_confidence_score < 25).length,
    vpnDetected: enrichedData.filter(ip => ip.vpnapi_security_vpn || ip.is_vpn).length,
  };

  // Generate map markers
  const markers = enrichedData.map(ip => {
    const coords = getCoordinates(ip.country, ip.city);
    const isVpn = ip.vpnapi_security_vpn || ip.is_vpn;
    const severity = getSeverity(ip.abuse_confidence_score, isVpn);
    
    const flags: string[] = [];
    if (ip.abuse_confidence_score >= 75) flags.push(`${ip.total_reports} Reports`);
    if (isVpn) flags.push('VPN');
    if (ip.vpnapi_security_proxy || ip.is_proxy) flags.push('Proxy');
    if (ip.vpnapi_security_tor || ip.is_tor) flags.push('Tor');
    if (ip.is_hosting) flags.push('Hosting');

    return {
      lat: coords.lat,
      lng: coords.lng,
      ip: ip.ip,
      severity,
      abuseScore: ip.abuse_confidence_score,
      city: ip.city,
      country: ip.country,
      org: ip.org,
      flags,
    };
  });

  // Generate summary text
  const criticalIPs = enrichedData.filter(ip => ip.abuse_confidence_score >= 90);
  const highRiskIPs = enrichedData.filter(ip => ip.abuse_confidence_score >= 75 && ip.abuse_confidence_score < 90);

  // Generate standalone HTML map and save it
  const cyberprobeRoot = process.env.CYBERPROBE_ROOT || path.resolve(__dirname, '../../../');
  const timestamp = new Date().toISOString().slice(0, 10);
  const mapFilename = `ip_threat_map_${timestamp}.html`;
  const mapPath = path.join(cyberprobeRoot, 'reports', mapFilename);
  
  const htmlContent = generateStandaloneMapHTML(enrichedData, markers);
  fs.writeFileSync(mapPath, htmlContent, 'utf-8');
  
  // Auto-open in browser
  const openCommand = process.platform === 'win32' ? 'start' : process.platform === 'darwin' ? 'open' : 'xdg-open';
  exec(`${openCommand} "${mapPath}"`);

  let summary = `🌐 **IP Threat Analysis Complete**\n\n`;
  summary += `**Total IPs Analyzed:** ${statistics.total}\n`;
  summary += `**🔴 Critical (≥90%):** ${statistics.critical}\n`;
  summary += `**🟠 High (75-89%):** ${statistics.high}\n`;
  summary += `**🟡 Medium (25-74%):** ${statistics.medium}\n`;
  summary += `**🟢 Clean (<25%):** ${statistics.clean}\n`;
  if (statistics.vpnDetected > 0) {
    summary += `**🔒 VPN/Proxy Detected:** ${statistics.vpnDetected}\n`;
  }

  if (criticalIPs.length > 0) {
    summary += `\n**⚠️ CRITICAL THREATS:**\n`;
    criticalIPs.forEach(ip => {
      summary += `- ${ip.ip} (${ip.city}, ${ip.country}) - ${ip.abuse_confidence_score}% abuse, ${ip.total_reports} reports\n`;
      summary += `  ISP: ${ip.org}\n`;
    });
  }

  if (highRiskIPs.length > 0) {
    summary += `\n**🚨 HIGH RISK:**\n`;
    highRiskIPs.forEach(ip => {
      summary += `- ${ip.ip} (${ip.city}, ${ip.country}) - ${ip.abuse_confidence_score}% abuse, ${ip.total_reports} reports\n`;
    });
  }

  summary += `\n📍 **Interactive map opened in browser** → [${mapFilename}](reports/${mapFilename})`;

  return {
    summary,
    enrichmentData: {
      ips: enrichedData,
      statistics,
      markers,
    },
  };
}
