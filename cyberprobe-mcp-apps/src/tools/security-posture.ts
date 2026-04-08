/**
 * Security Posture Dashboard Tool
 *
 * Types, validation helpers, and standalone HTML report generation for
 * the Defender for Servers security posture dashboard MCP app.
 */

// ───── Types ─────────────────────────────────────────────

export interface Subscription {
  name: string;
  running: number;
  deallocated: number;
  total: number;
}

export interface AVDevice {
  name: string;
  os: string;
  signature: string;
  daysBehind: number;
  exposure: string;
  sensor: string;
  chokePoint?: string;
  tags?: string[];
}

export interface ExposureDevice {
  name: string;
  os: string;
  sensor: string;
  critVulns: number;
  highVulns: number;
  totalVulns: number;
  alerts30d: number;
  avAge: string;
  chokePoint?: string;
}

export interface ChokePoint {
  name: string;
  type: string;
  pathsBlocked: number;
  priority: string;
  details?: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  evidence: string;
  affected?: string;
  tactic?: string;
}

export interface BlindSpot {
  name: string;
  os: string;
  lastSeen: string;
  avSignature: string;
  daysOffline: number;
}

export interface Recommendation {
  priority: string;
  title: string;
  description: string;
}

export interface PostureData {
  title?: string;
  reportDate?: string;
  vmInventory: {
    total: number;
    running: number;
    deallocated: number;
    subscriptions: Subscription[];
  };
  costs: {
    monthlyP2: number;
    annualP2: number;
    monthlyCompute: number;
    securityRatio: number;
  };
  avCompliance: {
    current: number;
    slightlyOutdated: number;
    outdated: number;
    criticallyOutdated: number;
    latestSignature: string;
    devices: AVDevice[];
  };
  exposure: {
    devices: ExposureDevice[];
  };
  attackPaths: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
    chokePoints: ChokePoint[];
  };
  cspm: {
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  blindSpots: BlindSpot[];
  mitre: MitreTechnique[];
  recommendations: Recommendation[];
}

// ───── Summary Generation ────────────────────────────────

export function generateSummary(data: PostureData): string {
  const av = data.avCompliance;
  const totalDevices = av.current + av.slightlyOutdated + av.outdated + av.criticallyOutdated;
  const compliancePct = totalDevices > 0 ? Math.round((av.current / totalDevices) * 100) : 0;
  const topChoke = data.attackPaths.chokePoints.sort((a, b) => b.pathsBlocked - a.pathsBlocked)[0];

  let summary = `## 🛡️ Security Posture Dashboard\n\n`;
  summary += `**${data.vmInventory.total} VMs** enrolled across ${data.vmInventory.subscriptions.length} subscriptions `;
  summary += `(${data.vmInventory.running} running, ${data.vmInventory.deallocated} deallocated)\n\n`;

  summary += `### Key Metrics\n`;
  summary += `| Metric | Value |\n|--------|-------|\n`;
  summary += `| AV Compliance | ${compliancePct}% current (${av.criticallyOutdated} critically outdated) |\n`;
  summary += `| Attack Paths | ${data.attackPaths.total} total (${data.attackPaths.critical} critical) |\n`;
  summary += `| CSPM Findings | ${data.cspm.total.toLocaleString()} (${data.cspm.high.toLocaleString()} high) |\n`;
  summary += `| Blind Spots | ${data.blindSpots.length} devices |\n`;
  summary += `| Monthly P2 Cost | $${data.costs.monthlyP2.toLocaleString()} |\n`;

  if (topChoke) {
    summary += `\n### ⚠️ Top Choke Point: ${topChoke.name}\n`;
    summary += `${topChoke.type} — blocks **${topChoke.pathsBlocked}** attack paths\n`;
  }

  if (data.blindSpots.length > 0) {
    summary += `\n### 👁️ Blind Spots (Inactive Sensor + Outdated AV)\n`;
    summary += data.blindSpots.map(b => `- **${b.name}** (${b.os}) — last seen ${b.lastSeen}`).join('\n');
  }

  return summary;
}

// ───── Standalone HTML Report ────────────────────────────

export function generatePostureReportHTML(data: PostureData): string {
  const d = data;
  const av = d.avCompliance;
  const totalDevices = av.current + av.slightlyOutdated + av.outdated + av.criticallyOutdated || 1;
  const title = d.title ?? 'Defender for Servers — Security Posture Report';
  const reportDate = d.reportDate ?? new Date().toISOString().slice(0, 10);

  // Build device rows
  const avDeviceRows = av.devices.map(dev => `
    <tr${dev.chokePoint ? ' class="highlight"' : ''} data-tags="${(dev.tags ?? []).join(' ')} ${dev.daysBehind > 30 ? 'critical' : ''} ${dev.chokePoint ? 'choke' : ''} ${dev.sensor === 'Inactive' ? 'inactive' : ''}">
      <td><strong>${dev.name}</strong></td>
      <td>${dev.os}</td>
      <td>${dev.signature}</td>
      <td data-sort="${dev.daysBehind}">${dev.daysBehind >= 600 ? '600+' : dev.daysBehind}</td>
      <td><span class="badge badge-${dev.exposure === 'High' ? 'critical' : 'medium'}">${dev.exposure}</span></td>
      <td>${dev.sensor === 'Inactive' ? '<span class="badge badge-inactive">Inactive</span>' : dev.sensor === 'Active' ? '<span class="badge badge-active">Active</span>' : '—'}</td>
      <td>${dev.chokePoint ? `<span class="badge badge-choke">⚡ ${dev.chokePoint}</span>` : '—'}</td>
    </tr>`).join('');

  const exposureRows = d.exposure.devices.map(dev => `
    <tr${dev.chokePoint ? ' class="highlight"' : ''}>
      <td><strong>${dev.name}</strong>${dev.chokePoint ? ' <span class="badge badge-choke">Choke</span>' : ''}</td>
      <td>${dev.os}</td>
      <td>${dev.sensor === 'Inactive' ? '<span class="badge badge-inactive">Inactive</span>' : '<span class="badge badge-active">Active</span>'}</td>
      <td data-sort="${dev.critVulns}" style="color:var(--accent-red);font-weight:${dev.critVulns > 10 ? 700 : 400};">${dev.critVulns}</td>
      <td data-sort="${dev.highVulns}" style="color:var(--accent-orange);">${dev.highVulns.toLocaleString()}</td>
      <td data-sort="${dev.totalVulns}">${dev.totalVulns.toLocaleString()}</td>
      <td data-sort="${dev.alerts30d}" style="${dev.alerts30d > 50 ? 'color:var(--accent-red);font-weight:700;' : ''}">${dev.alerts30d}</td>
      <td>${dev.avAge}</td>
    </tr>`).join('');

  const blindSpotRows = d.blindSpots.map(b => `
    <tr><td><strong>${b.name}</strong></td><td>${b.os}</td><td>${b.lastSeen}</td><td>${b.avSignature}</td><td>${b.daysOffline}</td></tr>`).join('');

  const chokePointCards = d.attackPaths.chokePoints.map(cp => `
    <div class="info-box critical-box">
      <h3 style="color:var(--accent-red);margin-bottom:6px;">${cp.name} <span class="badge badge-${cp.priority.toLowerCase()}">${cp.priority}</span></h3>
      <div style="display:grid;grid-template-columns:140px 1fr;gap:2px 10px;font-size:0.88rem;">
        <span style="color:var(--text-secondary);">Type:</span><span>${cp.type}</span>
        <span style="color:var(--text-secondary);">Paths Blocked:</span><span style="color:var(--accent-red);font-weight:700;">${cp.pathsBlocked}</span>
        ${cp.details ? `<span style="color:var(--text-secondary);">Details:</span><span>${cp.details}</span>` : ''}
      </div>
    </div>`).join('');

  const mitreCards = d.mitre.map(t => `
    <div class="mitre-card" onclick="this.classList.toggle('expanded')">
      <div class="mitre-id">${t.id}</div>
      <div class="mitre-name">${t.name}</div>
      <div class="mitre-evidence">${t.evidence}</div>
      <div class="detail-toggle">${t.affected ? `<strong>Affected:</strong> ${t.affected}<br>` : ''}${t.tactic ? `<strong>Tactic:</strong> ${t.tactic}` : ''}</div>
    </div>`).join('');

  const recItems = d.recommendations.map(r => {
    const pClass = r.priority === 'P1' ? 'rec-p1' : r.priority === 'P2' ? 'rec-p2' : 'rec-p3';
    return `<div class="rec-item" onclick="toggleRec(this)">
      <div class="rec-check ${pClass}">${r.priority}</div>
      <div class="rec-content"><strong>${r.title}</strong><p>${r.description}</p></div>
    </div>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title}</title>
<style>
:root{--bg-primary:#0d1117;--bg-secondary:#161b22;--bg-card:#21262d;--bg-hover:#292e36;--text-primary:#e6edf3;--text-secondary:#8b949e;--border-color:#30363d;--accent-red:#f85149;--accent-orange:#d29922;--accent-yellow:#e3b341;--accent-green:#3fb950;--accent-blue:#58a6ff;--accent-purple:#a371f7;--accent-cyan:#39d2c0;--sidebar-width:260px;}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg-primary);color:var(--text-primary);line-height:1.6;}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:var(--sidebar-width);background:var(--bg-secondary);border-right:1px solid var(--border-color);overflow-y:auto;z-index:100;}
.sidebar-header{padding:20px 18px 14px;border-bottom:1px solid var(--border-color);}
.sidebar-header h2{font-size:1rem;background:linear-gradient(90deg,var(--accent-blue),var(--accent-purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.sidebar-header .date{color:var(--text-secondary);font-size:0.78rem;margin-top:4px;}
.nav-item{display:flex;align-items:center;gap:10px;padding:8px 18px;cursor:pointer;color:var(--text-secondary);font-size:0.88rem;transition:all 0.15s;text-decoration:none;border-left:3px solid transparent;}
.nav-item:hover{background:var(--bg-card);color:var(--text-primary);}
.nav-item.active{background:rgba(88,166,255,0.08);color:var(--accent-blue);border-left-color:var(--accent-blue);}
.main{margin-left:var(--sidebar-width);padding:24px 32px 60px;}
.page-header{background:linear-gradient(135deg,#1a1f29,#0d1117);border:1px solid var(--border-color);border-radius:12px;padding:28px 32px;margin-bottom:24px;text-align:center;}
.page-header h1{font-size:1.8rem;background:linear-gradient(90deg,var(--accent-blue),var(--accent-purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:24px;}
.kpi-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:10px;padding:18px;text-align:center;position:relative;overflow:hidden;}
.kpi-value{font-size:2rem;font-weight:700;line-height:1.1;}
.kpi-label{color:var(--text-secondary);font-size:0.82rem;margin-top:4px;}
.section{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:10px;margin-bottom:24px;overflow:hidden;}
.section-header{padding:18px 24px;cursor:pointer;display:flex;align-items:center;justify-content:space-between;}
.section-header:hover{background:var(--bg-card);}
.section-header h2{font-size:1.2rem;}
.section-body{padding:0 24px 22px;}
.section.collapsed .section-body{display:none;}
table{width:100%;border-collapse:collapse;font-size:0.85rem;}
thead th{background:var(--bg-card);color:var(--accent-blue);text-align:left;padding:10px 12px;font-weight:600;cursor:pointer;white-space:nowrap;user-select:none;}
thead th:hover{color:var(--accent-cyan);}
tbody td{padding:9px 12px;border-bottom:1px solid var(--border-color);}
tbody tr:hover{background:rgba(88,166,255,0.04);}
tbody tr.highlight{background:rgba(248,81,73,0.06);}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.73rem;font-weight:600;text-transform:uppercase;}
.badge-critical{background:rgba(248,81,73,0.18);color:var(--accent-red);border:1px solid rgba(248,81,73,0.4);}
.badge-high{background:rgba(210,153,34,0.18);color:var(--accent-orange);border:1px solid rgba(210,153,34,0.4);}
.badge-medium{background:rgba(227,179,65,0.18);color:var(--accent-yellow);border:1px solid rgba(227,179,65,0.4);}
.badge-low{background:rgba(63,185,80,0.18);color:var(--accent-green);border:1px solid rgba(63,185,80,0.4);}
.badge-active{background:rgba(63,185,80,0.18);color:var(--accent-green);border:1px solid rgba(63,185,80,0.4);}
.badge-inactive{background:rgba(248,81,73,0.18);color:var(--accent-red);border:1px solid rgba(248,81,73,0.4);}
.badge-choke{background:rgba(163,113,247,0.2);color:var(--accent-purple);border:1px solid rgba(163,113,247,0.5);font-weight:700;}
.info-box{background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px 20px;margin-bottom:14px;}
.info-box.critical-box{border-left:4px solid var(--accent-red);}
.info-box.warning-box{border-left:4px solid var(--accent-orange);}
.search-box{width:100%;padding:8px 14px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;color:var(--text-primary);font-size:0.88rem;outline:none;margin-bottom:12px;}
.search-box:focus{border-color:var(--accent-blue);}
.search-box::placeholder{color:var(--text-secondary);}
.filter-btn{padding:7px 16px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;color:var(--text-secondary);font-size:0.82rem;cursor:pointer;transition:all 0.15s;}
.filter-btn:hover{background:var(--bg-hover);color:var(--text-primary);}
.filter-btn.active{background:rgba(88,166,255,0.15);border-color:var(--accent-blue);color:var(--accent-blue);}
.cost-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;}
.cost-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:10px;padding:20px;}
.cost-amount{font-size:1.8rem;font-weight:700;color:var(--accent-blue);}
.cost-desc{color:var(--text-secondary);font-size:0.85rem;margin-top:4px;}
.mitre-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:14px 18px;cursor:pointer;transition:all 0.15s;margin-bottom:8px;}
.mitre-card:hover{border-color:var(--accent-purple);}
.mitre-id{color:var(--accent-purple);font-weight:700;font-size:0.85rem;}
.mitre-name{font-weight:600;margin:2px 0 6px;}
.mitre-evidence{color:var(--text-secondary);font-size:0.83rem;}
.mitre-card .detail-toggle{display:none;margin-top:10px;padding-top:10px;border-top:1px solid var(--border-color);font-size:0.82rem;}
.mitre-card.expanded .detail-toggle{display:block;}
.rec-item{display:flex;gap:14px;padding:14px 16px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;margin-bottom:10px;cursor:pointer;transition:all 0.15s;}
.rec-item:hover{border-color:var(--accent-blue);}
.rec-item.done{opacity:0.5;text-decoration:line-through;}
.rec-check{flex-shrink:0;width:28px;height:28px;border-radius:50%;border:2px solid var(--border-color);display:flex;align-items:center;justify-content:center;font-size:0.8rem;transition:all 0.2s;}
.rec-item.done .rec-check{background:var(--accent-green);border-color:var(--accent-green);}
.rec-p1{border-color:var(--accent-red);color:var(--accent-red);}
.rec-p2{border-color:var(--accent-orange);color:var(--accent-orange);}
.rec-p3{border-color:var(--accent-yellow);color:var(--accent-yellow);}
.rec-content{flex:1;}
.rec-content strong{display:block;margin-bottom:3px;}
.rec-content p{color:var(--text-secondary);font-size:0.85rem;}
footer{text-align:center;color:var(--text-secondary);font-size:0.78rem;padding:24px 0;border-top:1px solid var(--border-color);}
@media(max-width:900px){.sidebar{display:none;}.main{margin-left:0;}}
</style>
</head>
<body>
<nav class="sidebar">
  <div class="sidebar-header"><h2>🛡️ ${title}</h2><div class="date">${reportDate}</div></div>
  <a class="nav-item active" href="#summary">📋 Executive Summary</a>
  <a class="nav-item" href="#costs">💰 Cost Analysis</a>
  <a class="nav-item" href="#av">🦠 AV Compliance</a>
  <a class="nav-item" href="#exposure">🎯 Exposure</a>
  <a class="nav-item" href="#attacks">🔗 Attack Paths</a>
  <a class="nav-item" href="#cspm">📊 CSPM</a>
  <a class="nav-item" href="#blind-spots">👁️ Blind Spots</a>
  <a class="nav-item" href="#mitre">🗺️ MITRE</a>
  <a class="nav-item" href="#recs">✅ Recommendations</a>
</nav>
<div class="main">
  <div class="page-header"><h1>🛡️ ${title}</h1><div style="color:var(--text-secondary);">${reportDate} • Generated by CyberProbe MCP App</div></div>

  <div class="kpi-grid">
    <div class="kpi-card"><div class="kpi-value" style="color:var(--accent-blue);">${d.vmInventory.total}</div><div class="kpi-label">Total VMs</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:var(--accent-green);">${d.vmInventory.running}</div><div class="kpi-label">Running</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:var(--accent-red);">${av.criticallyOutdated}</div><div class="kpi-label">Outdated AV</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:var(--accent-purple);">${d.attackPaths.total}</div><div class="kpi-label">Attack Paths</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:var(--accent-red);">${d.attackPaths.critical}</div><div class="kpi-label">Critical</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:var(--accent-yellow);">${d.cspm.total.toLocaleString()}</div><div class="kpi-label">CSPM Findings</div></div>
  </div>

  <div class="section" id="summary"><div class="section-header" onclick="this.closest('.section').classList.toggle('collapsed')"><h2>📋 Executive Summary</h2><span>▼</span></div>
    <div class="section-body">
      <div class="info-box critical-box"><strong style="color:var(--accent-red);">⚠️ Critical:</strong> ${av.criticallyOutdated} devices with critically outdated AV. ${d.attackPaths.chokePoints.length} choke points identified.</div>
      ${d.blindSpots.length > 0 ? `<div class="info-box warning-box"><strong style="color:var(--accent-orange);">👁️ Blind Spots:</strong> ${d.blindSpots.length} devices with inactive sensors AND outdated AV.</div>` : ''}
    </div>
  </div>

  <div class="section" id="costs"><div class="section-header" onclick="this.closest('.section').classList.toggle('collapsed')"><h2>💰 Cost Analysis</h2><span>▼</span></div>
    <div class="section-body"><div class="cost-grid">
      <div class="cost-card"><div class="cost-amount">$${d.costs.monthlyP2.toLocaleString()}</div><div class="cost-desc">P2 / Month (${d.vmInventory.running} VMs × $15)</div></div>
      <div class="cost-card"><div class="cost-amount">$${d.costs.annualP2.toLocaleString()}</div><div class="cost-desc">Annual P2 Cost</div></div>
      <div class="cost-card"><div class="cost-amount">~$${d.costs.monthlyCompute.toLocaleString()}</div><div class="cost-desc">Monthly VM Compute</div></div>
      <div class="cost-card"><div class="cost-amount" style="color:var(--accent-green);">${d.costs.securityRatio}%</div><div class="cost-desc">Security / Compute Ratio</div></div>
    </div></div>
  </div>

  <div class="section" id="av"><div class="section-header" onclick="this.closest('.section').classList.toggle('collapsed')"><h2>🦠 AV Compliance</h2><span>▼</span></div>
    <div class="section-body">
      <p style="color:var(--text-secondary);margin-bottom:16px;">Latest: <strong style="color:var(--accent-green);">${av.latestSignature}</strong></p>
      <div style="display:flex;height:24px;border-radius:6px;overflow:hidden;margin-bottom:16px;">
        <div style="width:${(av.current/totalDevices*100).toFixed(1)}%;background:var(--accent-green);" title="Current: ${av.current}"></div>
        <div style="width:${(av.slightlyOutdated/totalDevices*100).toFixed(1)}%;background:var(--accent-yellow);" title="Slightly: ${av.slightlyOutdated}"></div>
        <div style="width:${(av.outdated/totalDevices*100).toFixed(1)}%;background:var(--accent-orange);" title="Outdated: ${av.outdated}"></div>
        <div style="width:${(av.criticallyOutdated/totalDevices*100).toFixed(1)}%;background:var(--accent-red);" title="Critical: ${av.criticallyOutdated}"></div>
      </div>
      <input class="search-box" type="text" id="avSearch" placeholder="🔍 Search devices..." oninput="filterAV()">
      <div style="display:flex;gap:8px;margin-bottom:12px;">
        <button class="filter-btn active" onclick="setAVFilter(this,'all')">All</button>
        <button class="filter-btn" onclick="setAVFilter(this,'critical')">Critical</button>
        <button class="filter-btn" onclick="setAVFilter(this,'choke')">Choke Points</button>
        <button class="filter-btn" onclick="setAVFilter(this,'inactive')">Inactive</button>
      </div>
      <div style="overflow-x:auto;">
      <table id="avTable">
        <thead><tr>
          <th onclick="sortT('avTable',0)">Device</th><th onclick="sortT('avTable',1)">OS</th>
          <th onclick="sortT('avTable',2)">Signature</th><th onclick="sortT('avTable',3)">Days Behind</th>
          <th onclick="sortT('avTable',4)">Exposure</th><th onclick="sortT('avTable',5)">Sensor</th><th>Choke</th>
        </tr></thead>
        <tbody>${avDeviceRows}</tbody>
      </table>
      </div>
    </div>
  </div>

  <div class="section" id="exposure"><div class="section-header" onclick="this.closest('.section').classList.toggle('collapsed')"><h2>🎯 Exposure & Vulnerability Analysis</h2><span>▼</span></div>
    <div class="section-body">
      <div style="overflow-x:auto;">
      <table id="expTable">
        <thead><tr>
          <th onclick="sortT('expTable',0)">Device</th><th onclick="sortT('expTable',1)">OS</th>
          <th onclick="sortT('expTable',2)">Sensor</th><th onclick="sortT('expTable',3)">Critical</th>
          <th onclick="sortT('expTable',4)">High</th><th onclick="sortT('expTable',5)">Total</th>
          <th onclick="sortT('expTable',6)">Alerts</th><th>AV Age</th>
        </tr></thead>
        <tbody>${exposureRows}</tbody>
      </table>
      </div>
    </div>
  </div>

  <div class="section" id="attacks"><div class="section-header" onclick="this.closest('.section').classList.toggle('collapsed')"><h2>🔗 Attack Paths & Choke Points</h2><span>▼</span></div>
    <div class="section-body">
      <p style="margin-bottom:12px;">${d.attackPaths.total} attack paths (${d.attackPaths.critical} Critical, ${d.attackPaths.high} High, ${d.attackPaths.medium} Medium, ${d.attackPaths.low} Low)</p>
      ${chokePointCards}
    </div>
  </div>

  <div class="section" id="cspm"><div class="section-header" onclick="this.closest('.section').classList.toggle('collapsed')"><h2>📊 CSPM Findings</h2><span>▼</span></div>
    <div class="section-body">
      <table><thead><tr><th>Severity</th><th>Count</th><th>%</th></tr></thead><tbody>
        <tr><td><span class="badge badge-critical">High</span></td><td>${d.cspm.high.toLocaleString()}</td><td>${(d.cspm.high/(d.cspm.total||1)*100).toFixed(1)}%</td></tr>
        <tr><td><span class="badge badge-medium">Medium</span></td><td>${d.cspm.medium.toLocaleString()}</td><td>${(d.cspm.medium/(d.cspm.total||1)*100).toFixed(1)}%</td></tr>
        <tr><td><span class="badge badge-low">Low</span></td><td>${d.cspm.low.toLocaleString()}</td><td>${(d.cspm.low/(d.cspm.total||1)*100).toFixed(1)}%</td></tr>
      </tbody></table>
    </div>
  </div>

  ${d.blindSpots.length > 0 ? `
  <div class="section" id="blind-spots"><div class="section-header" onclick="this.closest('.section').classList.toggle('collapsed')"><h2>👁️ Blind Spots</h2><span>▼</span></div>
    <div class="section-body">
      <table><thead><tr><th>Device</th><th>OS</th><th>Last Seen</th><th>AV Signature</th><th>Days Offline</th></tr></thead>
      <tbody>${blindSpotRows}</tbody></table>
    </div>
  </div>` : ''}

  ${d.mitre.length > 0 ? `
  <div class="section" id="mitre"><div class="section-header" onclick="this.closest('.section').classList.toggle('collapsed')"><h2>🗺️ MITRE ATT&CK</h2><span>▼</span></div>
    <div class="section-body"><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px;">${mitreCards}</div></div>
  </div>` : ''}

  <div class="section" id="recs"><div class="section-header" onclick="this.closest('.section').classList.toggle('collapsed')"><h2>✅ Recommendations</h2><span>▼</span></div>
    <div class="section-body">${recItems}</div>
  </div>

  <footer>${title} • ${reportDate} • Generated by CyberProbe MCP App</footer>
</div>

<script>
let avFilter='all';
function setAVFilter(btn,f){document.querySelectorAll('#av .filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');avFilter=f;filterAV();}
function filterAV(){const q=document.getElementById('avSearch').value.toLowerCase();document.querySelectorAll('#avTable tbody tr').forEach(r=>{const t=r.textContent.toLowerCase();const tags=r.getAttribute('data-tags')||'';const ms=!q||t.includes(q);let mf=true;if(avFilter==='critical')mf=tags.includes('critical');else if(avFilter==='choke')mf=tags.includes('choke');else if(avFilter==='inactive')mf=tags.includes('inactive');r.style.display=ms&&mf?'':'none';});}
function sortT(id,c){const t=document.getElementById(id);const tb=t.querySelector('tbody');const rows=Array.from(tb.rows);const th=t.querySelectorAll('thead th')[c];const a=!th.classList.contains('sa');t.querySelectorAll('thead th').forEach(h=>{h.classList.remove('sa','sd');});th.classList.add(a?'sa':'sd');rows.sort((x,y)=>{let av=x.cells[c].getAttribute('data-sort')||x.cells[c].textContent.trim();let bv=y.cells[c].getAttribute('data-sort')||y.cells[c].textContent.trim();const an=parseFloat(String(av).replace(/[^0-9.-]/g,''));const bn=parseFloat(String(bv).replace(/[^0-9.-]/g,''));if(!isNaN(an)&&!isNaN(bn))return a?an-bn:bn-an;return a?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));});rows.forEach(r=>tb.appendChild(r));}
function toggleRec(el){el.classList.toggle('done');const ch=el.querySelector('.rec-check');ch.textContent=el.classList.contains('done')?'✓':ch.classList.contains('rec-p1')?'P1':ch.classList.contains('rec-p2')?'P2':'P3';}
</script>
</body>
</html>`;
}
