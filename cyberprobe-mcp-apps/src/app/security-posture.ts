/**
 * CyberProbe Security Posture Dashboard - MCP Apps Client
 *
 * Runs inside the MCP Apps iframe. Receives security posture data from the
 * server-side tool via `ontoolresult` and renders an interactive compact
 * dashboard with tabbed navigation, sortable tables, and filters.
 */

import { App } from '@modelcontextprotocol/ext-apps';

// ───── Types ─────────────────────────────────────────────
interface Subscription { name: string; running: number; deallocated: number; total: number; }
interface AVDevice {
  name: string; os: string; signature: string; daysBehind: number;
  exposure: string; sensor: string; chokePoint?: string; tags?: string[];
}
interface ExposureDevice {
  name: string; os: string; sensor: string;
  critVulns: number; highVulns: number; totalVulns: number;
  alerts30d: number; avAge: string; chokePoint?: string;
}
interface ChokePoint {
  name: string; type: string; pathsBlocked: number;
  priority: string; details?: string;
}
interface MitreTechnique { id: string; name: string; evidence: string; affected?: string; tactic?: string; }
interface BlindSpot { name: string; os: string; lastSeen: string; avSignature: string; daysOffline: number; }
interface Recommendation { priority: string; title: string; description: string; }

interface PostureData {
  title?: string;
  reportDate?: string;
  vmInventory: {
    total: number; running: number; deallocated: number;
    subscriptions: Subscription[];
  };
  costs: { monthlyP2: number; annualP2: number; monthlyCompute: number; securityRatio: number; };
  avCompliance: {
    current: number; slightlyOutdated: number; outdated: number; criticallyOutdated: number;
    latestSignature: string;
    devices: AVDevice[];
  };
  exposure: { devices: ExposureDevice[]; };
  attackPaths: {
    critical: number; high: number; medium: number; low: number; total: number;
    chokePoints: ChokePoint[];
  };
  cspm: { high: number; medium: number; low: number; total: number; };
  blindSpots: BlindSpot[];
  mitre: MitreTechnique[];
  recommendations: Recommendation[];
}

// ───── DOM refs ──────────────────────────────────────────
const loading = document.getElementById('loading')!;
const tabBar = document.getElementById('tabBar')!;
const reportDateEl = document.getElementById('reportDate')!;
const titleEl = document.getElementById('title')!;
const footerStatus = document.getElementById('footerStatus')!;
const openReportBtn = document.getElementById('openReportBtn') as HTMLButtonElement;

// ───── State ─────────────────────────────────────────────
let postureData: PostureData | null = null;
let currentAVFilter = 'all';
let reportFileUri: string | null = null;

// ───── Init MCP App ──────────────────────────────────────
const app = new App({
  name: 'CyberProbe Security Posture',
  version: '2.0.0',
});

app.onthemechange = (theme) => {
  document.documentElement.setAttribute('data-theme', theme.mode);
};

// Request fullscreen on connect to maximize the dashboard
async function requestFullscreen() {
  try {
    const ctx = app.getHostContext?.();
    if (ctx?.availableDisplayModes?.includes?.('fullscreen')) {
      const result = await app.requestDisplayMode({ mode: 'fullscreen' });
      console.log('Display mode:', result.mode);
      document.body.classList.toggle('fullscreen', result.mode === 'fullscreen');
    }
  } catch (e) {
    console.log('Fullscreen not available:', e);
  }
}

// Add fullscreen toggle to header
const fsBtn = document.getElementById('fullscreenBtn');
if (fsBtn) {
  fsBtn.addEventListener('click', async () => {
    try {
      const ctx = app.getHostContext?.();
      const current = ctx?.displayMode ?? 'inline';
      const target = current === 'fullscreen' ? 'inline' : 'fullscreen';
      const result = await app.requestDisplayMode({ mode: target });
      document.body.classList.toggle('fullscreen', result.mode === 'fullscreen');
      fsBtn.textContent = result.mode === 'fullscreen' ? '⊟' : '⊞';
      fsBtn.title = result.mode === 'fullscreen' ? 'Exit fullscreen' : 'Fullscreen';
    } catch (e) { console.log('Toggle failed:', e); }
  });
}

app.ontoolresult = (result: any) => {
  console.log('Received posture data:', result);
  // Capture report path from server _meta
  if (result._meta?.reportPath) {
    reportFileUri = result._meta.reportPath;
  }

  const data: PostureData | undefined =
    result._meta?.postureData ??
    result.postureData ??
    tryParseFromContent(result);
  if (data) {
    postureData = data;
    render(data);
  } else {
    loading.innerHTML = '<span style="color:var(--accent-red);">No posture data received.</span>';
  }
};

function tryParseFromContent(result: any): PostureData | undefined {
  const text = result?.content?.find((c: any) => c.type === 'text')?.text;
  if (text) {
    try { return JSON.parse(text); } catch { /* noop */ }
  }
  return undefined;
}

// ───── Tabs ──────────────────────────────────────────────
tabBar.addEventListener('click', (e) => {
  const tab = (e.target as HTMLElement).closest('.tab') as HTMLElement | null;
  if (!tab) return;
  const id = tab.dataset.tab!;
  tabBar.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  tab.classList.add('active');
  document.querySelectorAll('.tab-panel').forEach(p => (p as HTMLElement).style.display = 'none');
  const panel = document.getElementById(`panel-${id}`);
  if (panel) { panel.style.display = 'block'; panel.classList.add('active'); }
});

// ───── Render ────────────────────────────────────────────
function render(d: PostureData) {
  loading.style.display = 'none';
  if (d.title) titleEl.textContent = d.title;
  reportDateEl.textContent = d.reportDate ?? new Date().toLocaleDateString();
  footerStatus.textContent = `${d.vmInventory.total} VMs • ${d.attackPaths.total} Attack Paths • ${d.cspm.total} CSPM Findings`;
  openReportBtn.style.display = '';
  openReportBtn.onclick = async () => {
    try {
      if (reportFileUri) {
        await app.openLink({ url: reportFileUri });
      }
    } catch (e) {
      console.log('openLink failed, falling back:', e);
      // Fallback: try window.open
      if (reportFileUri) window.open(reportFileUri, '_blank');
    }
  };

  // Request fullscreen after data arrives for max visibility
  requestFullscreen();

  // Notify host of desired size
  try {
    app.sendSizeChanged({ width: 900, height: 700 });
  } catch (_) { /* ignore if not supported */ }

  // Show first panel
  const first = document.getElementById('panel-overview')!;
  first.style.display = 'block';

  renderOverview(d);
  renderAV(d);
  renderExposure(d);
  renderAttacks(d);
  renderRecs(d);
}

// ───── OVERVIEW ──────────────────────────────────────────
function renderOverview(d: PostureData) {
  const grid = document.getElementById('kpiGrid')!;
  const kpis = [
    { val: d.vmInventory.total, lbl: 'Total VMs', color: 'var(--accent-blue)' },
    { val: d.vmInventory.running, lbl: 'Running', color: 'var(--accent-green)' },
    { val: d.avCompliance.criticallyOutdated, lbl: 'Outdated AV', color: 'var(--accent-red)' },
    { val: d.attackPaths.total, lbl: 'Attack Paths', color: 'var(--accent-purple)' },
    { val: d.attackPaths.critical, lbl: 'Critical Paths', color: 'var(--accent-red)' },
    { val: d.cspm.total.toLocaleString(), lbl: 'CSPM Findings', color: 'var(--accent-yellow)' },
    { val: `$${d.costs.monthlyP2.toLocaleString()}`, lbl: 'P2/Month', color: 'var(--accent-blue)' },
  ];
  grid.innerHTML = kpis.map(k =>
    `<div class="kpi"><div class="kpi-val" style="color:${k.color}">${k.val}</div><div class="kpi-lbl">${k.lbl}</div></div>`
  ).join('');

  // Top risk card
  if (d.attackPaths.chokePoints.length > 0) {
    const top = d.attackPaths.chokePoints.sort((a, b) => b.pathsBlocked - a.pathsBlocked)[0];
    const card = document.getElementById('topRiskCard')!;
    card.style.display = '';
    card.innerHTML = `<h3 style="color:var(--accent-red);">⚠️ Top Choke Point: ${top.name}</h3>
      <p>${top.type} — blocks ${top.pathsBlocked} attack paths${top.details ? ' • ' + top.details : ''}</p>`;
  }

  // Blind spots
  if (d.blindSpots.length > 0) {
    const card = document.getElementById('blindSpotCard')!;
    card.style.display = '';
    card.innerHTML = `<h3 style="color:var(--accent-orange);">👁️ ${d.blindSpots.length} Monitoring Blind Spots</h3>
      <p>Inactive sensor + outdated AV: ${d.blindSpots.map(b => b.name).join(', ')}</p>`;
  }

  // CSPM bar
  const cspmEl = document.getElementById('cspmBar')!;
  const t = d.cspm.total || 1;
  cspmEl.innerHTML = `
    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-primary);">CSPM Findings</div>
    <div class="stacked-bar">
      <div style="width:${(d.cspm.high/t*100).toFixed(1)}%;background:var(--accent-red);" title="High: ${d.cspm.high}"></div>
      <div style="width:${(d.cspm.medium/t*100).toFixed(1)}%;background:var(--accent-yellow);" title="Medium: ${d.cspm.medium}"></div>
      <div style="width:${(d.cspm.low/t*100).toFixed(1)}%;background:var(--accent-green);" title="Low: ${d.cspm.low}"></div>
    </div>
    <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text-muted);margin-top:2px;">
      <span>High: ${d.cspm.high.toLocaleString()}</span>
      <span>Medium: ${d.cspm.medium.toLocaleString()}</span>
      <span>Low: ${d.cspm.low.toLocaleString()}</span>
    </div>`;
}

// ───── AV COMPLIANCE ─────────────────────────────────────
function renderAV(d: PostureData) {
  const av = d.avCompliance;
  const total = av.current + av.slightlyOutdated + av.outdated + av.criticallyOutdated || 1;

  // Summary
  document.getElementById('avSummary')!.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-bottom:8px;">
      <div class="kpi" style="padding:6px;"><div class="kpi-val" style="font-size:16px;color:var(--accent-green);">${av.current}</div><div class="kpi-lbl">Current</div></div>
      <div class="kpi" style="padding:6px;"><div class="kpi-val" style="font-size:16px;color:var(--accent-yellow);">${av.slightlyOutdated}</div><div class="kpi-lbl">Slight</div></div>
      <div class="kpi" style="padding:6px;"><div class="kpi-val" style="font-size:16px;color:var(--accent-orange);">${av.outdated}</div><div class="kpi-lbl">Outdated</div></div>
      <div class="kpi" style="padding:6px;"><div class="kpi-val" style="font-size:16px;color:var(--accent-red);">${av.criticallyOutdated}</div><div class="kpi-lbl">Critical</div></div>
    </div>`;

  // Bar
  document.getElementById('avBar')!.innerHTML = `
    <div class="stacked-bar">
      <div style="width:${(av.current/total*100).toFixed(1)}%;background:var(--accent-green);"></div>
      <div style="width:${(av.slightlyOutdated/total*100).toFixed(1)}%;background:var(--accent-yellow);"></div>
      <div style="width:${(av.outdated/total*100).toFixed(1)}%;background:var(--accent-orange);"></div>
      <div style="width:${(av.criticallyOutdated/total*100).toFixed(1)}%;background:var(--accent-red);"></div>
    </div>`;

  // Filters
  const filtersEl = document.getElementById('avFilters')!;
  filtersEl.innerHTML = [
    { id: 'all', label: `All (${av.devices.length})` },
    { id: 'critical', label: 'Critical' },
    { id: 'choke', label: 'Choke Points' },
    { id: 'inactive', label: 'Inactive Sensor' },
  ].map(f => `<button class="filter-btn${f.id === 'all' ? ' active' : ''}" data-filter="${f.id}">${f.label}</button>`).join('');

  filtersEl.addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement).closest('.filter-btn') as HTMLElement | null;
    if (!btn) return;
    filtersEl.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentAVFilter = btn.dataset.filter!;
    filterAVRows();
  });

  // Table
  const table = document.getElementById('avTable')!;
  const thead = table.querySelector('thead')!;
  thead.innerHTML = `<tr>
    <th data-col="0">Device</th>
    <th data-col="1">OS</th>
    <th data-col="2">Signature</th>
    <th data-col="3">Days Behind</th>
    <th data-col="4">Exposure</th>
    <th data-col="5">Sensor</th>
    <th data-col="6">Choke</th>
  </tr>`;
  thead.addEventListener('click', (e) => {
    const th = (e.target as HTMLElement).closest('th') as HTMLElement | null;
    if (th) sortTableByCol('avTable', parseInt(th.dataset.col!, 10));
  });

  const tbody = table.querySelector('tbody')!;
  tbody.innerHTML = av.devices.map(dev => {
    const tags = (dev.tags ?? []).concat(
      dev.daysBehind > 30 ? ['critical'] : [],
      dev.chokePoint ? ['choke'] : [],
      dev.sensor === 'Inactive' ? ['inactive'] : []
    ).join(' ');
    const isHighlight = dev.chokePoint ? ' highlight' : '';
    return `<tr class="${isHighlight}" data-tags="${tags}">
      <td><strong>${dev.name}</strong></td>
      <td>${dev.os}</td>
      <td>${dev.signature}</td>
      <td data-sort="${dev.daysBehind}">${dev.daysBehind >= 600 ? '600+' : dev.daysBehind}</td>
      <td><span class="badge badge-${dev.exposure === 'High' ? 'critical' : 'medium'}">${dev.exposure}</span></td>
      <td>${dev.sensor === 'Inactive' ? '<span class="badge badge-inactive">Inactive</span>' : dev.sensor === 'Active' ? '<span class="badge badge-active">Active</span>' : '—'}</td>
      <td>${dev.chokePoint ? `<span class="badge badge-choke">⚡ ${dev.chokePoint}</span>` : '—'}</td>
    </tr>`;
  }).join('');

  // Search
  document.getElementById('avSearch')!.addEventListener('input', () => filterAVRows());
}

function filterAVRows() {
  const search = (document.getElementById('avSearch') as HTMLInputElement).value.toLowerCase();
  document.querySelectorAll('#avTable tbody tr').forEach((r) => {
    const row = r as HTMLElement;
    const text = row.textContent!.toLowerCase();
    const tags = row.dataset.tags ?? '';
    const matchSearch = !search || text.includes(search);
    let matchFilter = true;
    if (currentAVFilter === 'critical') matchFilter = tags.includes('critical');
    else if (currentAVFilter === 'choke') matchFilter = tags.includes('choke');
    else if (currentAVFilter === 'inactive') matchFilter = tags.includes('inactive');
    row.style.display = matchSearch && matchFilter ? '' : 'none';
  });
}

// ───── EXPOSURE ──────────────────────────────────────────
function renderExposure(d: PostureData) {
  const table = document.getElementById('expTable')!;
  table.querySelector('thead')!.innerHTML = `<tr>
    <th data-col="0">Device</th>
    <th data-col="1">OS</th>
    <th data-col="2">Sensor</th>
    <th data-col="3">Crit</th>
    <th data-col="4">High</th>
    <th data-col="5">Total</th>
    <th data-col="6">Alerts</th>
    <th data-col="7">AV Age</th>
  </tr>`;
  table.querySelector('thead')!.addEventListener('click', (e) => {
    const th = (e.target as HTMLElement).closest('th') as HTMLElement | null;
    if (th) sortTableByCol('expTable', parseInt(th.dataset.col!, 10));
  });

  table.querySelector('tbody')!.innerHTML = d.exposure.devices.map(dev => {
    const hl = dev.chokePoint ? ' highlight' : '';
    return `<tr class="${hl}">
      <td><strong>${dev.name}</strong>${dev.chokePoint ? ` <span class="badge badge-choke">Choke</span>` : ''}</td>
      <td>${dev.os}</td>
      <td>${dev.sensor === 'Inactive' ? '<span class="badge badge-inactive">Inactive</span>' : '<span class="badge badge-active">Active</span>'}</td>
      <td data-sort="${dev.critVulns}" style="color:var(--accent-red);font-weight:${dev.critVulns > 10 ? 700 : 400};">${dev.critVulns}</td>
      <td data-sort="${dev.highVulns}" style="color:var(--accent-orange);">${dev.highVulns.toLocaleString()}</td>
      <td data-sort="${dev.totalVulns}">${dev.totalVulns.toLocaleString()}</td>
      <td data-sort="${dev.alerts30d}" style="${dev.alerts30d > 50 ? 'color:var(--accent-red);font-weight:700;' : ''}">${dev.alerts30d}</td>
      <td>${dev.avAge}</td>
    </tr>`;
  }).join('');

  document.getElementById('expSearch')!.addEventListener('input', (e) => {
    const q = (e.target as HTMLInputElement).value.toLowerCase();
    document.querySelectorAll('#expTable tbody tr').forEach(r => {
      (r as HTMLElement).style.display = !q || r.textContent!.toLowerCase().includes(q) ? '' : 'none';
    });
  });
}

// ───── ATTACK PATHS ──────────────────────────────────────
function renderAttacks(d: PostureData) {
  const ap = d.attackPaths;
  const kpis = document.getElementById('attackKpis')!;
  kpis.innerHTML = `
    <div class="kpi-grid" style="margin-bottom:10px;">
      <div class="kpi"><div class="kpi-val" style="color:var(--accent-red);">${ap.critical}</div><div class="kpi-lbl">Critical</div></div>
      <div class="kpi"><div class="kpi-val" style="color:var(--accent-orange);">${ap.high}</div><div class="kpi-lbl">High</div></div>
      <div class="kpi"><div class="kpi-val" style="color:var(--accent-yellow);">${ap.medium}</div><div class="kpi-lbl">Medium</div></div>
      <div class="kpi"><div class="kpi-val" style="color:var(--accent-green);">${ap.low}</div><div class="kpi-lbl">Low</div></div>
      <div class="kpi"><div class="kpi-val" style="color:var(--accent-blue);">${ap.total}</div><div class="kpi-lbl">Total</div></div>
    </div>`;

  // Choke points
  const cpEl = document.getElementById('chokePoints')!;
  cpEl.innerHTML = '<h3 style="font-size:13px;margin-bottom:6px;">Choke Points</h3>' +
    ap.chokePoints.map(cp => `
      <div class="info-card critical" style="cursor:pointer;">
        <h3 style="color:var(--accent-red);font-size:12px;">${cp.name} <span class="badge badge-${cp.priority.toLowerCase()}">${cp.priority}</span></h3>
        <div class="detail-grid">
          <span class="label">Type</span><span class="val">${cp.type}</span>
          <span class="label">Paths Blocked</span><span class="val" style="color:var(--accent-red);">${cp.pathsBlocked}</span>
          ${cp.details ? `<span class="label">Details</span><span class="val">${cp.details}</span>` : ''}
        </div>
      </div>`
    ).join('');

  // MITRE
  const mitreEl = document.getElementById('mitreCards')!;
  if (d.mitre.length > 0) {
    mitreEl.innerHTML = '<h3 style="font-size:13px;margin-bottom:6px;">MITRE ATT&CK</h3>' +
      d.mitre.map(t => `
        <div class="mitre-card">
          <span class="mitre-id">${t.id}</span>
          <span class="mitre-name" style="margin-left:6px;">${t.name}</span>
          <div class="mitre-ev">${t.evidence}</div>
        </div>`
      ).join('');
  }
}

// ───── RECOMMENDATIONS ───────────────────────────────────
function renderRecs(d: PostureData) {
  const list = document.getElementById('recList')!;
  list.innerHTML = d.recommendations.map((r, i) => {
    const pClass = r.priority === 'P1' ? 'rec-p1' : r.priority === 'P2' ? 'rec-p2' : 'rec-p3';
    return `<div class="rec" data-idx="${i}">
      <div class="rec-badge ${pClass}">${r.priority}</div>
      <div class="rec-content"><strong>${r.title}</strong><p>${r.description}</p></div>
    </div>`;
  }).join('');

  list.addEventListener('click', (e) => {
    const rec = (e.target as HTMLElement).closest('.rec') as HTMLElement | null;
    if (!rec) return;
    rec.classList.toggle('done');
    const badge = rec.querySelector('.rec-badge')!;
    if (rec.classList.contains('done')) {
      badge.textContent = '✓';
    } else {
      const idx = parseInt(rec.dataset.idx!, 10);
      badge.textContent = d.recommendations[idx].priority;
    }
    const total = list.querySelectorAll('.rec').length;
    const done = list.querySelectorAll('.rec.done').length;
    document.getElementById('recStatus')!.textContent = `${done}/${total} completed`;
  });
}

// ───── TABLE SORT ────────────────────────────────────────
function sortTableByCol(tableId: string, colIdx: number) {
  const table = document.getElementById(tableId)!;
  const tbody = table.querySelector('tbody')!;
  const rows = Array.from(tbody.rows);
  const th = table.querySelectorAll('thead th')[colIdx] as HTMLElement;
  const asc = !th.classList.contains('sorted-asc');
  table.querySelectorAll('thead th').forEach(h => h.classList.remove('sorted-asc', 'sorted-desc'));
  th.classList.add(asc ? 'sorted-asc' : 'sorted-desc');
  rows.sort((a, b) => {
    const aVal = a.cells[colIdx].getAttribute('data-sort') ?? a.cells[colIdx].textContent!.trim();
    const bVal = b.cells[colIdx].getAttribute('data-sort') ?? b.cells[colIdx].textContent!.trim();
    const aNum = parseFloat(String(aVal).replace(/[^0-9.-]/g, ''));
    const bNum = parseFloat(String(bVal).replace(/[^0-9.-]/g, ''));
    if (!isNaN(aNum) && !isNaN(bNum)) return asc ? aNum - bNum : bNum - aNum;
    return asc ? String(aVal).localeCompare(String(bVal)) : String(bVal).localeCompare(String(aVal));
  });
  rows.forEach(r => tbody.appendChild(r));
}

// ───── Connect ───────────────────────────────────────────
app.connect().catch((err) => {
  console.error('Failed to connect to MCP host:', err);
  loading.innerHTML = '<span style="color:var(--accent-red);">Failed to connect</span>';
});

(window as any).cyberprobePosture = app;
