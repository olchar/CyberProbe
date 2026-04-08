/**
 * Response Actions Console Tool
 *
 * Types, validation helpers, summary generation, and standalone HTML report
 * generation for the Defender Response Actions MCP app.
 */

// ───── Types ─────────────────────────────────────────────

export interface ResponseAction {
  id?: string;
  type: 'device' | 'identity' | 'incident' | 'forensic';
  action: string;
  target: string;
  status: 'Succeeded' | 'Pending' | 'InProgress' | 'Failed' | 'Cancelled' | 'planned';
  timestamp?: string;
  requestor?: string;
  comment?: string;
  details?: Record<string, string | number | boolean>;
}

export interface PlaybookStep {
  action: string;
  tool: string;
  status?: string;
}

export interface Playbook {
  name: string;
  icon: string;
  trigger: string;
  steps: PlaybookStep[];
}

export interface ResponseData {
  title?: string;
  reportDate?: string;
  actions: ResponseAction[];
  playbooks?: Playbook[];
  summary?: {
    totalActions: number;
    succeeded: number;
    pending: number;
    inProgress: number;
    failed: number;
    devicesIsolated: number;
    usersDisabled: number;
    scansRunning: number;
    forensicsCollected: number;
  };
}

// ───── Summary Generation ────────────────────────────────

export function computeSummary(actions: ResponseAction[]) {
  return {
    totalActions: actions.length,
    succeeded: actions.filter(a => a.status === 'Succeeded').length,
    pending: actions.filter(a => a.status === 'Pending' || a.status === 'planned').length,
    inProgress: actions.filter(a => a.status === 'InProgress').length,
    failed: actions.filter(a => a.status === 'Failed').length,
    devicesIsolated: actions.filter(a => a.type === 'device' && a.action.toLowerCase().includes('isolat') && a.status === 'Succeeded').length,
    usersDisabled: actions.filter(a => a.type === 'identity' && a.action.toLowerCase().includes('disable') && a.status === 'Succeeded').length,
    scansRunning: actions.filter(a => a.action.toLowerCase().includes('scan') && (a.status === 'InProgress' || a.status === 'Pending')).length,
    forensicsCollected: actions.filter(a => a.type === 'forensic' && a.status === 'Succeeded').length,
  };
}

export function generateSummary(data: ResponseData): string {
  const s = data.summary || computeSummary(data.actions);
  const deviceActions = data.actions.filter(a => a.type === 'device');
  const identityActions = data.actions.filter(a => a.type === 'identity');
  const incidentActions = data.actions.filter(a => a.type === 'incident');
  const forensicActions = data.actions.filter(a => a.type === 'forensic');

  let md = `## 🛡️ Response Actions Console\n\n`;
  md += `**${s.totalActions} total actions** tracked | `;
  md += `✅ ${s.succeeded} succeeded | ⏳ ${s.pending + s.inProgress} pending | ❌ ${s.failed} failed\n\n`;

  md += `### Key Metrics\n`;
  md += `| Metric | Value |\n|--------|-------|\n`;
  md += `| Device Actions | ${deviceActions.length} |\n`;
  md += `| Identity Actions | ${identityActions.length} |\n`;
  md += `| Incident Management | ${incidentActions.length} |\n`;
  md += `| Forensic Collections | ${forensicActions.length} |\n`;
  md += `| Devices Isolated | ${s.devicesIsolated} |\n`;
  md += `| Users Disabled | ${s.usersDisabled} |\n`;
  md += `| Scans Running | ${s.scansRunning} |\n`;

  if (s.failed > 0) {
    const failedActions = data.actions.filter(a => a.status === 'Failed');
    md += `\n### ❌ Failed Actions\n`;
    failedActions.forEach(a => {
      md += `- **${a.action}** on \`${a.target}\`${a.comment ? ` — ${a.comment}` : ''}\n`;
    });
  }

  return md;
}

// ───── Standalone HTML Report ────────────────────────────

function actionIcon(action: string): string {
  const a = action.toLowerCase();
  if (a.includes('isolat')) return '🔒';
  if (a.includes('release') || a.includes('unisolat')) return '🔓';
  if (a.includes('scan') || a.includes('antivirus')) return '🔍';
  if (a.includes('quarantine') || a.includes('stop')) return '⛔';
  if (a.includes('restrict')) return '🚫';
  if (a.includes('disable')) return '🚷';
  if (a.includes('enable')) return '✅';
  if (a.includes('password') || a.includes('reset')) return '🔑';
  if (a.includes('compromised')) return '⚠️';
  if (a.includes('safe')) return '✅';
  if (a.includes('comment')) return '💬';
  if (a.includes('tag')) return '🏷️';
  if (a.includes('assign')) return '👤';
  if (a.includes('classif')) return '📋';
  if (a.includes('status')) return '📊';
  if (a.includes('collect') || a.includes('forensic') || a.includes('package')) return '📦';
  return '🛡️';
}

function statusBadge(status: string): string {
  const s = status.toLowerCase();
  let cls = 'badge-info';
  if (s === 'succeeded') cls = 'badge-active';
  else if (s === 'pending' || s === 'planned') cls = 'badge-medium';
  else if (s === 'inprogress') cls = 'badge-high';
  else if (s === 'failed') cls = 'badge-critical';
  else if (s === 'cancelled') cls = 'badge-inactive';
  return `<span class="badge ${cls}">${status}</span>`;
}

function defaultPlaybooks(): Playbook[] {
  return [
    {
      name: 'Compromised User Account',
      icon: '🔐',
      trigger: 'Account compromise confirmed',
      steps: [
        { action: 'Confirm user compromised', tool: 'defender_confirm_user_compromised' },
        { action: 'Disable AD account', tool: 'defender_disable_ad_account' },
        { action: 'Force password reset', tool: 'defender_force_ad_password_reset' },
        { action: 'Isolate user devices', tool: 'defender_isolate_device' },
        { action: 'Document actions', tool: 'defender_add_incident_comment' },
        { action: 'Classify incident', tool: 'defender_classify_incident' },
      ],
    },
    {
      name: 'Malware Containment',
      icon: '🦠',
      trigger: 'Active malware detected on endpoint',
      steps: [
        { action: 'Isolate device', tool: 'defender_isolate_device' },
        { action: 'Stop & quarantine malware', tool: 'defender_stop_and_quarantine' },
        { action: 'Restrict code execution', tool: 'defender_restrict_code_execution' },
        { action: 'Run AV scan', tool: 'defender_run_antivirus_scan' },
        { action: 'Collect forensic package', tool: 'defender_collect_investigation_package' },
      ],
    },
    {
      name: 'Ransomware / Bulk Containment',
      icon: '🚨',
      trigger: 'Multiple devices compromised, lateral movement',
      steps: [
        { action: 'Bulk isolate affected devices', tool: 'defender_isolate_multiple' },
        { action: 'Disable affected user accounts', tool: 'defender_disable_ad_account (×N)' },
        { action: 'Restrict code execution on all', tool: 'defender_restrict_code_execution (×N)' },
        { action: 'Run AV scans on all devices', tool: 'defender_run_antivirus_scan (×N)' },
        { action: 'Collect forensics from patient zero', tool: 'defender_collect_investigation_package' },
      ],
    },
    {
      name: 'Post-Remediation Recovery',
      icon: '🔄',
      trigger: 'Threat eradicated, ready to restore',
      steps: [
        { action: 'Verify AV scan results', tool: 'defender_get_machine_actions' },
        { action: 'Release device from isolation', tool: 'defender_release_device' },
        { action: 'Re-enable user account', tool: 'defender_enable_ad_account' },
        { action: 'Confirm user safe', tool: 'defender_confirm_user_safe' },
        { action: 'Resolve incident', tool: 'defender_update_incident_status' },
      ],
    },
  ];
}

export function generateResponseActionsHTML(data: ResponseData): string {
  const title = data.title ?? 'CyberProbe — Response Actions Console';
  const reportDate = data.reportDate ?? new Date().toISOString().slice(0, 10);
  const s = data.summary || computeSummary(data.actions);
  const playbooks = data.playbooks || defaultPlaybooks();

  const deviceActions = data.actions.filter(a => a.type === 'device');
  const identityActions = data.actions.filter(a => a.type === 'identity');
  const incidentActions = data.actions.filter(a => a.type === 'incident');
  const forensicActions = data.actions.filter(a => a.type === 'forensic');

  // Build action card HTML
  const buildActionCard = (a: ResponseAction) => {
    const detailsHtml = a.details
      ? Object.entries(a.details).map(([k, v]) => `<span class="detail-chip">${k}: ${v}</span>`).join('')
      : '';
    const time = a.timestamp ? new Date(a.timestamp).toLocaleString() : '';
    return `
      <div class="action-card">
        <div class="action-header">
          <span class="action-icon">${actionIcon(a.action)}</span>
          <span class="action-name">${a.action}</span>
          ${statusBadge(a.status)}
        </div>
        <div class="action-target">${a.target}</div>
        ${a.comment ? `<div class="action-comment">${a.comment}</div>` : ''}
        ${detailsHtml ? `<div class="details-row">${detailsHtml}</div>` : ''}
        <div class="action-footer">
          <span>${time}</span>
          ${a.requestor ? `<span>by ${a.requestor}</span>` : ''}
        </div>
      </div>`;
  };

  const buildSection = (label: string, icon: string, actions: ResponseAction[]) => {
    if (actions.length === 0) return `
      <div class="section">
        <div class="section-header"><h2>${icon} ${label}</h2></div>
        <div class="section-body"><div class="empty-state">${icon}<br>No ${label.toLowerCase()} recorded</div></div>
      </div>`;
    return `
      <div class="section">
        <div class="section-header" onclick="this.closest('.section').classList.toggle('collapsed')">
          <h2>${icon} ${label} (${actions.length})</h2><span>▼</span>
        </div>
        <div class="section-body"><div class="action-grid">${actions.map(buildActionCard).join('')}</div></div>
      </div>`;
  };

  const playbookCards = playbooks.map(pb => `
    <div class="playbook-card" onclick="this.classList.toggle('expanded')">
      <div class="playbook-header">
        <span>${pb.icon} <strong>${pb.name}</strong></span><span class="chevron">▶</span>
      </div>
      <div class="playbook-body">
        <div class="trigger-line">Trigger: ${pb.trigger}</div>
        ${pb.steps.map((step, i) => `
          <div class="pb-step">
            <div class="step-num">${i + 1}</div>
            <div><strong>${step.action}</strong><br><code>${step.tool}</code></div>
            ${step.status ? statusBadge(step.status) : ''}
          </div>
        `).join('')}
      </div>
    </div>`).join('');

  const historyRows = [...data.actions]
    .sort((a, b) => {
      const ta = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const tb = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      return tb - ta;
    })
    .map(a => `
      <tr>
        <td>${a.timestamp ? new Date(a.timestamp).toLocaleString() : '—'}</td>
        <td>${actionIcon(a.action)} ${a.action}</td>
        <td style="font-family:monospace;font-size:0.82rem;">${a.target}</td>
        <td>${statusBadge(a.status)}</td>
        <td>${a.requestor || '—'}</td>
      </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title}</title>
<style>
:root{--bg-primary:#0d1117;--bg-secondary:#161b22;--bg-card:#21262d;--bg-hover:#292e36;--text-primary:#e6edf3;--text-secondary:#8b949e;--border-color:#30363d;--accent-red:#f85149;--accent-orange:#d29922;--accent-yellow:#e3b341;--accent-green:#3fb950;--accent-blue:#58a6ff;--accent-purple:#a371f7;--accent-cyan:#39d2c0;--sidebar-width:240px;}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg-primary);color:var(--text-primary);line-height:1.6;}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:var(--sidebar-width);background:var(--bg-secondary);border-right:1px solid var(--border-color);overflow-y:auto;z-index:100;}
.sidebar-header{padding:20px 18px 14px;border-bottom:1px solid var(--border-color);}
.sidebar-header h2{font-size:1rem;background:linear-gradient(90deg,var(--accent-red),var(--accent-purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.sidebar-header .date{color:var(--text-secondary);font-size:0.78rem;margin-top:4px;}
.nav-item{display:flex;align-items:center;gap:10px;padding:8px 18px;cursor:pointer;color:var(--text-secondary);font-size:0.88rem;transition:all 0.15s;text-decoration:none;border-left:3px solid transparent;}
.nav-item:hover{background:var(--bg-card);color:var(--text-primary);}
.nav-item.active{background:rgba(248,81,73,0.08);color:var(--accent-red);border-left-color:var(--accent-red);}
.main{margin-left:var(--sidebar-width);padding:24px 32px 60px;}
.page-header{background:linear-gradient(135deg,#1a1f29,#0d1117);border:1px solid var(--border-color);border-radius:12px;padding:28px 32px;margin-bottom:24px;text-align:center;}
.page-header h1{font-size:1.8rem;background:linear-gradient(90deg,var(--accent-red),var(--accent-purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px;}
.kpi-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:10px;padding:18px;text-align:center;}
.kpi-value{font-size:2rem;font-weight:700;line-height:1.1;}
.kpi-label{color:var(--text-secondary);font-size:0.82rem;margin-top:4px;}
.section{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:10px;margin-bottom:24px;overflow:hidden;}
.section-header{padding:16px 24px;cursor:pointer;display:flex;align-items:center;justify-content:space-between;}
.section-header:hover{background:var(--bg-card);}
.section-header h2{font-size:1.1rem;}
.section-body{padding:0 24px 20px;}
.section.collapsed .section-body{display:none;}
.action-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px;}
.action-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:10px;padding:16px;transition:border-color 0.15s;}
.action-card:hover{border-color:var(--accent-blue);}
.action-header{display:flex;align-items:center;gap:8px;margin-bottom:8px;}
.action-icon{font-size:1.2rem;}
.action-name{font-weight:600;flex:1;}
.action-target{font-family:monospace;font-size:0.85rem;color:var(--accent-cyan);margin-bottom:6px;}
.action-comment{color:var(--text-secondary);font-size:0.83rem;margin-bottom:6px;}
.details-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px;}
.detail-chip{font-size:0.72rem;padding:2px 8px;border-radius:10px;background:rgba(88,166,255,0.12);color:var(--accent-blue);}
.action-footer{display:flex;justify-content:space-between;font-size:0.75rem;color:var(--text-secondary);}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.73rem;font-weight:600;text-transform:uppercase;}
.badge-critical{background:rgba(248,81,73,0.18);color:var(--accent-red);border:1px solid rgba(248,81,73,0.4);}
.badge-high{background:rgba(210,153,34,0.18);color:var(--accent-orange);border:1px solid rgba(210,153,34,0.4);}
.badge-medium{background:rgba(227,179,65,0.18);color:var(--accent-yellow);border:1px solid rgba(227,179,65,0.4);}
.badge-active{background:rgba(63,185,80,0.18);color:var(--accent-green);border:1px solid rgba(63,185,80,0.4);}
.badge-inactive{background:rgba(139,148,158,0.18);color:var(--text-secondary);border:1px solid rgba(139,148,158,0.4);}
.badge-info{background:rgba(88,166,255,0.18);color:var(--accent-blue);border:1px solid rgba(88,166,255,0.4);}
.empty-state{text-align:center;padding:40px;color:var(--text-secondary);font-size:1.5rem;}
table{width:100%;border-collapse:collapse;font-size:0.85rem;}
thead th{background:var(--bg-card);color:var(--accent-blue);text-align:left;padding:10px 12px;font-weight:600;cursor:pointer;user-select:none;white-space:nowrap;}
thead th:hover{color:var(--accent-cyan);}
tbody td{padding:9px 12px;border-bottom:1px solid var(--border-color);}
tbody tr:hover{background:rgba(88,166,255,0.04);}
.playbook-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:10px;margin-bottom:12px;overflow:hidden;cursor:pointer;transition:border-color 0.15s;}
.playbook-card:hover{border-color:var(--accent-purple);}
.playbook-header{padding:14px 18px;display:flex;justify-content:space-between;align-items:center;font-size:0.95rem;}
.playbook-body{display:none;padding:0 18px 16px;border-top:1px solid var(--border-color);}
.playbook-card.expanded .playbook-body{display:block;}
.playbook-card.expanded .chevron{transform:rotate(90deg);}
.chevron{transition:transform 0.2s;color:var(--text-secondary);}
.trigger-line{color:var(--text-secondary);font-size:0.82rem;margin:10px 0 8px;}
.pb-step{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border-color);}
.pb-step:last-child{border-bottom:none;}
.step-num{width:24px;height:24px;border-radius:50%;background:var(--accent-purple);color:#fff;font-size:0.72rem;display:flex;align-items:center;justify-content:center;flex-shrink:0;}
.pb-step code{color:var(--accent-cyan);font-size:0.8rem;}
.search-box{width:100%;padding:8px 14px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;color:var(--text-primary);font-size:0.88rem;outline:none;margin-bottom:12px;}
.search-box:focus{border-color:var(--accent-blue);}
.search-box::placeholder{color:var(--text-secondary);}
.filter-btn{padding:7px 16px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;color:var(--text-secondary);font-size:0.82rem;cursor:pointer;transition:all 0.15s;}
.filter-btn:hover{background:var(--bg-hover);color:var(--text-primary);}
.filter-btn.active{background:rgba(88,166,255,0.15);border-color:var(--accent-blue);color:var(--accent-blue);}
footer{text-align:center;color:var(--text-secondary);font-size:0.78rem;padding:24px 0;border-top:1px solid var(--border-color);}
@media(max-width:900px){.sidebar{display:none;}.main{margin-left:0;}}
</style>
</head>
<body>
<nav class="sidebar">
  <div class="sidebar-header"><h2>🛡️ Response Actions</h2><div class="date">${reportDate}</div></div>
  <a class="nav-item active" href="#overview" onclick="showPanel('overview',this)">📊 Overview</a>
  <a class="nav-item" href="#devices" onclick="showPanel('devices',this)">🖥️ Device Actions</a>
  <a class="nav-item" href="#identity" onclick="showPanel('identity',this)">👤 Identity Actions</a>
  <a class="nav-item" href="#incidents" onclick="showPanel('incidents',this)">📝 Incident Mgmt</a>
  <a class="nav-item" href="#forensics" onclick="showPanel('forensics',this)">🔬 Forensics</a>
  <a class="nav-item" href="#playbooks" onclick="showPanel('playbooks',this)">📋 Playbooks</a>
  <a class="nav-item" href="#history" onclick="showPanel('history',this)">📜 Action History</a>
</nav>
<div class="main">
  <div class="page-header">
    <h1>🛡️ ${title}</h1>
    <div style="color:var(--text-secondary);">${reportDate} • ${s.totalActions} response actions tracked • Generated by CyberProbe</div>
  </div>

  <!-- KPI Summary -->
  <div class="kpi-grid">
    <div class="kpi-card"><div class="kpi-value" style="color:var(--accent-blue);">${s.totalActions}</div><div class="kpi-label">Total Actions</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:var(--accent-green);">${s.succeeded}</div><div class="kpi-label">Succeeded</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:var(--accent-orange);">${s.pending + s.inProgress}</div><div class="kpi-label">Pending</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:var(--accent-red);">${s.failed}</div><div class="kpi-label">Failed</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:var(--accent-purple);">${s.devicesIsolated}</div><div class="kpi-label">Devices Isolated</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:var(--accent-cyan);">${s.usersDisabled}</div><div class="kpi-label">Users Disabled</div></div>
  </div>

  <div id="panel-overview">
    ${buildSection('Recent Device Actions', '🖥️', deviceActions.slice(0, 4))}
    ${buildSection('Recent Identity Actions', '👤', identityActions.slice(0, 4))}
  </div>

  <div id="panel-devices" style="display:none;">
    ${buildSection('Device Response Actions', '🖥️', deviceActions)}
  </div>

  <div id="panel-identity" style="display:none;">
    ${buildSection('Identity Response Actions', '👤', identityActions)}
  </div>

  <div id="panel-incidents" style="display:none;">
    ${buildSection('Incident Management Actions', '📝', incidentActions)}
  </div>

  <div id="panel-forensics" style="display:none;">
    ${buildSection('Forensic Collections', '🔬', forensicActions)}
  </div>

  <div id="panel-playbooks" style="display:none;">
    <div class="section">
      <div class="section-header"><h2>📋 Response Playbooks</h2></div>
      <div class="section-body">${playbookCards}</div>
    </div>
  </div>

  <div id="panel-history" style="display:none;">
    <div class="section">
      <div class="section-header"><h2>📜 Full Action History</h2></div>
      <div class="section-body">
        <input class="search-box" type="text" id="histSearch" placeholder="🔍 Search actions..." oninput="filterHistory()">
        <div style="display:flex;gap:8px;margin-bottom:12px;">
          <button class="filter-btn active" onclick="setHistFilter(this,'all')">All</button>
          <button class="filter-btn" onclick="setHistFilter(this,'Succeeded')">Succeeded</button>
          <button class="filter-btn" onclick="setHistFilter(this,'Pending')">Pending</button>
          <button class="filter-btn" onclick="setHistFilter(this,'InProgress')">In Progress</button>
          <button class="filter-btn" onclick="setHistFilter(this,'Failed')">Failed</button>
        </div>
        <div style="overflow-x:auto;">
        <table id="histTable">
          <thead><tr>
            <th onclick="sortT('histTable',0)">Time</th>
            <th onclick="sortT('histTable',1)">Action</th>
            <th onclick="sortT('histTable',2)">Target</th>
            <th onclick="sortT('histTable',3)">Status</th>
            <th>Requestor</th>
          </tr></thead>
          <tbody>${historyRows}</tbody>
        </table>
        </div>
      </div>
    </div>
  </div>

  <footer>${title} • ${reportDate} • Generated by CyberProbe MCP App</footer>
</div>

<script>
const panels=['overview','devices','identity','incidents','forensics','playbooks','history'];
function showPanel(name,el){panels.forEach(p=>{const e=document.getElementById('panel-'+p);if(e)e.style.display=p===name?'block':'none';});document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));if(el)el.classList.add('active');}
let histFilter='all';
function setHistFilter(btn,f){document.querySelectorAll('#panel-history .filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');histFilter=f;filterHistory();}
function filterHistory(){const q=(document.getElementById('histSearch')||{value:''}).value.toLowerCase();document.querySelectorAll('#histTable tbody tr').forEach(r=>{const t=r.textContent.toLowerCase();const ms=!q||t.includes(q);const mf=histFilter==='all'||r.cells[3].textContent.trim()===histFilter;r.style.display=ms&&mf?'':'none';});}
function sortT(id,c){const t=document.getElementById(id);const tb=t.querySelector('tbody');const rows=Array.from(tb.rows);const th=t.querySelectorAll('thead th')[c];const a=!th.classList.contains('asc');t.querySelectorAll('thead th').forEach(h=>{h.classList.remove('asc','desc');});th.classList.add(a?'asc':'desc');rows.sort((x,y)=>{let av=x.cells[c].textContent.trim();let bv=y.cells[c].textContent.trim();return a?av.localeCompare(bv):bv.localeCompare(av);});rows.forEach(r=>tb.appendChild(r));}
</script>
</body>
</html>`;
}
