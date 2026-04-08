/**
 * Entity Explorer Tool
 * 
 * Provides interactive entity list visualization for security investigations.
 * Supports IPs, Users, Devices, Domains, Files, and other entity types.
 */

export interface Entity {
  type: 'ip' | 'user' | 'device' | 'domain' | 'email' | 'file' | 'hash' | 'url' | 'process' | 'alert';
  value: string;
  name?: string;
  description?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  tags?: string[];
  details?: Record<string, string | number | boolean>;
  actions?: Array<{
    label: string;
    action: string;
    icon?: string;
    primary?: boolean;
  }>;
}

export interface EntityListResult {
  summary: string;
  entities: Entity[];
}

/**
 * Convert IP enrichment data to Entity format
 */
export function ipToEntity(ip: any): Entity {
  const abuseScore = ip.abuse_confidence_score || 0;
  let severity: Entity['severity'] = 'info';
  
  if (abuseScore >= 90) severity = 'critical';
  else if (abuseScore >= 75) severity = 'high';
  else if (abuseScore >= 25) severity = 'medium';
  else if (abuseScore > 0) severity = 'low';
  
  const tags: string[] = [];
  if (ip.vpnapi_security_vpn || ip.is_vpn) tags.push('VPN');
  if (ip.vpnapi_security_proxy || ip.is_proxy) tags.push('Proxy');
  if (ip.vpnapi_security_tor || ip.is_tor) tags.push('Tor');
  if (ip.is_hosting) tags.push('Hosting');
  if (abuseScore === 0) tags.push('Clean');
  
  return {
    type: 'ip',
    value: ip.ip,
    name: ip.ip,
    description: `${ip.city || 'Unknown'}, ${ip.country || 'Unknown'} • ${ip.org || 'Unknown ISP'}`,
    severity,
    tags,
    details: {
      'City': ip.city || 'Unknown',
      'Region': ip.region || 'Unknown',
      'Country': ip.country || 'Unknown',
      'Organization': ip.org || 'Unknown',
      'ASN': ip.asn || 'Unknown',
      'Timezone': ip.timezone || 'Unknown',
      'Abuse Score': `${abuseScore}%`,
      'Total Reports': ip.total_reports || 0,
    },
    actions: [
      { label: '🔍 Investigate', action: 'investigate', primary: true },
      { label: '📋 Copy', action: 'copy' },
      { label: '🚫 Block', action: 'block' },
    ],
  };
}

/**
 * Convert user data to Entity format
 */
export function userToEntity(user: any): Entity {
  const riskScore = user.riskScore || user.risk_score || 0;
  let severity: Entity['severity'] = 'info';
  
  if (riskScore >= 90) severity = 'critical';
  else if (riskScore >= 70) severity = 'high';
  else if (riskScore >= 40) severity = 'medium';
  else if (riskScore > 0) severity = 'low';
  
  const tags: string[] = [];
  if (user.isCompromised || user.is_compromised) tags.push('Compromised');
  if (user.isAdmin || user.is_admin) tags.push('Admin');
  if (user.mfaEnabled === false) tags.push('No MFA');
  if (user.department) tags.push(user.department);
  
  const upn = user.userPrincipalName || user.upn || user.email || user.id;
  const displayName = user.displayName || user.display_name || user.name || upn.split('@')[0];
  
  return {
    type: 'user',
    value: upn,
    name: displayName,
    description: `${user.jobTitle || user.job_title || 'User'} • ${user.department || 'Unknown Dept'}`,
    severity,
    tags,
    details: {
      'UPN': upn,
      'Display Name': displayName,
      'Department': user.department || 'Unknown',
      'Job Title': user.jobTitle || user.job_title || 'Unknown',
      'Manager': user.manager || 'Unknown',
      'Location': user.officeLocation || user.location || 'Unknown',
      'Risk Score': riskScore > 0 ? `${riskScore}%` : 'N/A',
      'Last Sign-in': user.lastSignIn || user.last_signin || 'Unknown',
    },
    actions: [
      { label: '👤 Profile', action: 'profile', primary: true },
      { label: '📊 Activity', action: 'activity' },
      { label: '🔒 Disable', action: 'disable' },
    ],
  };
}

/**
 * Convert device data to Entity format
 */
export function deviceToEntity(device: any): Entity {
  const riskScore = device.riskScore || device.risk_score || 0;
  let severity: Entity['severity'] = 'info';
  
  if (device.healthStatus === 'Critical' || riskScore >= 90) severity = 'critical';
  else if (device.healthStatus === 'Warning' || riskScore >= 70) severity = 'high';
  else if (riskScore >= 40) severity = 'medium';
  else if (riskScore > 0) severity = 'low';
  
  const tags: string[] = [];
  if (device.osPlatform) tags.push(device.osPlatform);
  if (device.healthStatus) tags.push(device.healthStatus);
  if (device.onboardingStatus === 'Onboarded') tags.push('Onboarded');
  
  return {
    type: 'device',
    value: device.id || device.deviceId || device.computerDnsName,
    name: device.computerDnsName || device.deviceName || device.name || 'Unknown Device',
    description: `${device.osPlatform || 'Unknown OS'} • Last seen: ${device.lastSeen || 'Unknown'}`,
    severity,
    tags,
    details: {
      'Device ID': device.id || device.deviceId || 'Unknown',
      'DNS Name': device.computerDnsName || 'Unknown',
      'OS': device.osPlatform || 'Unknown',
      'OS Version': device.osVersion || 'Unknown',
      'Health Status': device.healthStatus || 'Unknown',
      'Risk Score': riskScore > 0 ? `${riskScore}%` : 'N/A',
      'Last Seen': device.lastSeen || 'Unknown',
      'IP Address': device.lastIpAddress || device.ipAddress || 'Unknown',
    },
    actions: [
      { label: '💻 Details', action: 'details', primary: true },
      { label: '📜 Timeline', action: 'timeline' },
      { label: '🔒 Isolate', action: 'isolate' },
    ],
  };
}

/**
 * Convert alert data to Entity format
 */
export function alertToEntity(alert: any): Entity {
  const severity = (alert.severity || 'info').toLowerCase() as Entity['severity'];
  
  const tags: string[] = [];
  if (alert.status) tags.push(alert.status);
  if (alert.category) tags.push(alert.category);
  
  return {
    type: 'alert',
    value: alert.id || alert.alertId,
    name: alert.title || alert.name || 'Alert',
    description: alert.description || `${alert.category || 'Unknown'} alert`,
    severity,
    tags,
    details: {
      'Alert ID': alert.id || alert.alertId || 'Unknown',
      'Category': alert.category || 'Unknown',
      'Status': alert.status || 'Unknown',
      'Created': alert.createdTime || alert.createdDateTime || 'Unknown',
      'MITRE Tactics': (alert.mitreTactics || []).join(', ') || 'N/A',
      'Entities': alert.entityCount || 'Unknown',
    },
    actions: [
      { label: '🔍 Investigate', action: 'investigate', primary: true },
      { label: '✓ Resolve', action: 'resolve' },
      { label: '🔕 Suppress', action: 'suppress' },
    ],
  };
}

/**
 * Generic IOC to Entity converter
 */
export function iocToEntity(ioc: any): Entity {
  const type = detectIOCType(ioc.value || ioc);
  
  return {
    type,
    value: ioc.value || ioc,
    name: ioc.value || ioc,
    description: ioc.description || `${type.toUpperCase()} indicator`,
    severity: ioc.severity || 'info',
    tags: ioc.tags || [],
    details: ioc.details || {},
  };
}

/**
 * Detect IOC type from value
 */
function detectIOCType(value: string): Entity['type'] {
  if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(value)) return 'ip';
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value)) return 'hash';
  if (/^https?:\/\//i.test(value)) return 'url';
  if (/@/.test(value)) return 'email';
  if (/\.[a-z]{2,}$/i.test(value)) return 'domain';
  return 'file';
}

/**
 * Generate entities summary
 */
export function generateSummary(entities: Entity[]): string {
  const counts = {
    total: entities.length,
    critical: entities.filter(e => e.severity === 'critical').length,
    high: entities.filter(e => e.severity === 'high').length,
    medium: entities.filter(e => e.severity === 'medium').length,
    low: entities.filter(e => e.severity === 'low').length,
  };
  
  const typeCounts: Record<string, number> = {};
  entities.forEach(e => {
    typeCounts[e.type] = (typeCounts[e.type] || 0) + 1;
  });
  
  let summary = `🔎 **Entity Explorer** - ${counts.total} entities loaded\n\n`;
  
  if (counts.critical > 0) summary += `🔴 **${counts.critical} Critical**\n`;
  if (counts.high > 0) summary += `🟠 **${counts.high} High**\n`;
  if (counts.medium > 0) summary += `🟡 **${counts.medium} Medium**\n`;
  if (counts.low > 0) summary += `🟢 **${counts.low} Low**\n`;
  
  summary += '\n**By Type:**\n';
  Object.entries(typeCounts)
    .sort((a, b) => b[1] - a[1])
    .forEach(([type, count]) => {
      const icons: Record<string, string> = {
        ip: '🌐', user: '👤', device: '💻', domain: '🔗',
        email: '📧', file: '📄', hash: '🔐', url: '🌍',
        process: '⚙️', alert: '⚠️'
      };
      summary += `${icons[type] || '📌'} ${type}: ${count}\n`;
    });
  
  return summary;
}

/**
 * Generate standalone HTML for entity explorer (browser fallback)
 */
export function generateEntityExplorerHTML(entities: Entity[], title?: string): string {
  const typeIcons: Record<string, string> = {
    ip: '🌐', user: '👤', device: '💻', domain: '🔗',
    email: '📧', file: '📄', hash: '🔐', url: '🌍',
    process: '⚙️', alert: '⚠️'
  };
  
  const severityColors: Record<string, string> = {
    critical: '#f85149',
    high: '#d29922',
    medium: '#e3b341',
    low: '#3fb950',
    info: '#58a6ff'
  };
  
  const counts = {
    critical: entities.filter(e => e.severity === 'critical').length,
    high: entities.filter(e => e.severity === 'high').length,
    medium: entities.filter(e => e.severity === 'medium').length,
    low: entities.filter(e => e.severity === 'low').length,
    info: entities.filter(e => e.severity === 'info').length,
  };
  
  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sortedEntities = [...entities].sort((a, b) => {
    const sevA = severityOrder[a.severity || 'info'] ?? 5;
    const sevB = severityOrder[b.severity || 'info'] ?? 5;
    return sevA - sevB;
  });

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title || 'Entity Explorer'} - CyberProbe</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --bg-hover: #30363d;
            --border-color: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #c9d1d9;
            --text-muted: #8b949e;
            --accent-blue: #58a6ff;
            --accent-red: #f85149;
            --accent-orange: #d29922;
            --accent-yellow: #e3b341;
            --accent-green: #3fb950;
            --accent-purple: #a371f7;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-secondary);
            font-size: 13px;
            line-height: 1.5;
        }
        .container { display: flex; flex-direction: column; min-height: 100vh; }
        .header {
            background: var(--bg-secondary);
            padding: 16px 24px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            gap: 16px;
            align-items: center;
            flex-wrap: wrap;
        }
        .header h1 {
            font-size: 18px;
            font-weight: 600;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .search-box {
            flex: 1;
            min-width: 250px;
            position: relative;
        }
        .search-box input {
            width: 100%;
            padding: 8px 12px 8px 36px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 14px;
        }
        .search-box input:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.2);
        }
        .search-box::before {
            content: '🔍';
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 14px;
            opacity: 0.6;
        }
        .stats-bar {
            display: flex;
            gap: 20px;
            padding: 12px 24px;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            font-size: 13px;
        }
        .stat {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .stat-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }
        .filter-chips {
            display: flex;
            gap: 8px;
            padding: 12px 24px;
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            flex-wrap: wrap;
        }
        .chip {
            padding: 6px 12px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .chip:hover { background: var(--bg-hover); }
        .chip.active { background: var(--accent-blue); border-color: var(--accent-blue); color: white; }
        .entity-list { padding: 16px 24px; }
        .entity-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 12px;
            overflow: hidden;
            transition: border-color 0.2s;
        }
        .entity-card:hover { border-color: var(--accent-blue); }
        .entity-card.critical { border-left: 4px solid var(--accent-red); }
        .entity-card.high { border-left: 4px solid var(--accent-orange); }
        .entity-card.medium { border-left: 4px solid var(--accent-yellow); }
        .entity-card.low { border-left: 4px solid var(--accent-green); }
        .entity-card.info { border-left: 4px solid var(--accent-blue); }
        .entity-header {
            padding: 14px 16px;
            display: flex;
            align-items: center;
            gap: 12px;
            cursor: pointer;
        }
        .entity-icon {
            width: 40px;
            height: 40px;
            background: var(--bg-tertiary);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }
        .entity-main { flex: 1; min-width: 0; }
        .entity-title {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 2px;
        }
        .entity-subtitle {
            font-size: 12px;
            color: var(--text-muted);
        }
        .entity-badges { display: flex; gap: 6px; flex-wrap: wrap; }
        .badge {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
            text-transform: uppercase;
        }
        .badge.ip { background: rgba(88, 166, 255, 0.15); color: var(--accent-blue); }
        .badge.user { background: rgba(163, 113, 247, 0.15); color: var(--accent-purple); }
        .badge.device { background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }
        .badge.domain { background: rgba(210, 153, 34, 0.15); color: var(--accent-orange); }
        .badge.email { background: rgba(248, 81, 73, 0.15); color: var(--accent-red); }
        .badge.url { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); }
        .badge.alert { background: rgba(227, 179, 65, 0.15); color: var(--accent-yellow); }
        .badge.file { background: rgba(139, 148, 158, 0.15); color: var(--text-muted); }
        .badge.hash { background: rgba(163, 113, 247, 0.15); color: var(--accent-purple); }
        .tag { background: rgba(88, 166, 255, 0.1); color: var(--accent-blue); }
        .expand-icon { color: var(--text-muted); transition: transform 0.2s; font-size: 12px; }
        .entity-card.expanded .expand-icon { transform: rotate(90deg); }
        .entity-details {
            display: none;
            padding: 0 16px 16px;
            border-top: 1px solid var(--border-color);
            background: var(--bg-primary);
        }
        .entity-card.expanded .entity-details { display: block; }
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 10px;
            padding-top: 14px;
        }
        .detail-item {
            background: var(--bg-secondary);
            padding: 10px 12px;
            border-radius: 6px;
        }
        .detail-label {
            font-size: 10px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }
        .detail-value {
            font-size: 13px;
            color: var(--text-primary);
            word-break: break-all;
            cursor: pointer;
        }
        .detail-value:hover { color: var(--accent-blue); }
        .entity-actions {
            display: flex;
            gap: 8px;
            padding-top: 12px;
            border-top: 1px solid var(--border-color);
            margin-top: 12px;
        }
        .action-btn {
            padding: 8px 14px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-secondary);
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .action-btn:hover { background: var(--bg-hover); color: var(--text-primary); }
        .action-btn.primary { background: var(--accent-blue); border-color: var(--accent-blue); color: white; }
        .empty-state { text-align: center; padding: 60px; color: var(--text-muted); }
        .footer { padding: 16px 24px; text-align: center; color: var(--text-muted); font-size: 11px; border-top: 1px solid var(--border-color); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔎 ${title || 'Entity Explorer'}</h1>
            <div class="search-box">
                <input type="text" id="search" placeholder="Search entities..." oninput="filterEntities()">
            </div>
        </div>
        
        <div class="stats-bar">
            <div class="stat"><span class="stat-dot" style="background: #f85149;"></span> Critical: ${counts.critical}</div>
            <div class="stat"><span class="stat-dot" style="background: #d29922;"></span> High: ${counts.high}</div>
            <div class="stat"><span class="stat-dot" style="background: #e3b341;"></span> Medium: ${counts.medium}</div>
            <div class="stat"><span class="stat-dot" style="background: #3fb950;"></span> Low: ${counts.low}</div>
            <div class="stat"><span class="stat-dot" style="background: #58a6ff;"></span> Info: ${counts.info}</div>
            <div class="stat" style="margin-left: auto;">Total: ${entities.length}</div>
        </div>
        
        <div class="filter-chips" id="filter-chips">
            ${Object.entries(
              entities.reduce((acc, e) => { acc[e.type] = (acc[e.type] || 0) + 1; return acc; }, {} as Record<string, number>)
            ).sort((a, b) => b[1] - a[1]).map(([type, count]) => 
              `<div class="chip" data-type="${type}" onclick="toggleFilter('${type}')">${typeIcons[type] || '📌'} ${type} (${count})</div>`
            ).join('')}
        </div>
        
        <div class="entity-list" id="entity-list">
            ${sortedEntities.map((entity, idx) => {
              const icon = typeIcons[entity.type] || '📌';
              const severity = entity.severity || 'info';
              const badges = [`<span class="badge ${entity.type}">${entity.type}</span>`];
              (entity.tags || []).forEach(tag => badges.push(`<span class="badge tag">${tag}</span>`));
              
              const details = entity.details || {};
              const detailItems = Object.entries(details).map(([key, value]) => `
                <div class="detail-item">
                  <div class="detail-label">${key}</div>
                  <div class="detail-value" onclick="copyText('${String(value).replace(/'/g, "\\'")}')">${value}</div>
                </div>
              `).join('');
              
              return `
                <div class="entity-card ${severity}" data-idx="${idx}" data-type="${entity.type}" data-searchable="${[entity.value, entity.name, entity.description, ...(entity.tags || [])].join(' ').toLowerCase()}">
                  <div class="entity-header" onclick="toggleExpand(${idx})">
                    <div class="entity-icon">${icon}</div>
                    <div class="entity-main">
                      <div class="entity-title">${entity.name || entity.value}</div>
                      <div class="entity-subtitle">${entity.description || entity.type}</div>
                    </div>
                    <div class="entity-badges">${badges.join('')}</div>
                    <div class="expand-icon">▶</div>
                  </div>
                  <div class="entity-details">
                    <div class="detail-grid">
                      <div class="detail-item">
                        <div class="detail-label">Value</div>
                        <div class="detail-value" onclick="copyText('${entity.value}')">${entity.value}</div>
                      </div>
                      ${detailItems}
                    </div>
                    ${entity.actions ? `
                    <div class="entity-actions">
                      ${entity.actions.map(a => `<button class="action-btn ${a.primary ? 'primary' : ''}">${a.icon || ''} ${a.label}</button>`).join('')}
                    </div>
                    ` : ''}
                  </div>
                </div>
              `;
            }).join('')}
        </div>
        
        <div class="footer">Generated: ${new Date().toISOString().slice(0, 16).replace('T', ' ')} | CyberProbe Entity Explorer</div>
    </div>
    
    <script>
        const activeFilters = new Set();
        
        function toggleExpand(idx) {
            const card = document.querySelector(\`[data-idx="\${idx}"]\`);
            card.classList.toggle('expanded');
        }
        
        function toggleFilter(type) {
            const chip = document.querySelector(\`[data-type="\${type}"].chip\`);
            if (activeFilters.has(type)) {
                activeFilters.delete(type);
                chip.classList.remove('active');
            } else {
                activeFilters.add(type);
                chip.classList.add('active');
            }
            filterEntities();
        }
        
        function filterEntities() {
            const search = document.getElementById('search').value.toLowerCase();
            const cards = document.querySelectorAll('.entity-card');
            
            cards.forEach(card => {
                const type = card.dataset.type;
                const searchable = card.dataset.searchable;
                
                const matchesFilter = activeFilters.size === 0 || activeFilters.has(type);
                const matchesSearch = !search || searchable.includes(search);
                
                card.style.display = (matchesFilter && matchesSearch) ? 'block' : 'none';
            });
        }
        
        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => {
                // Optional: show feedback
            });
        }
    <\/script>
</body>
</html>`;
}
