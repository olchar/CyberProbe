/**
 * CyberProbe Response Actions Console - MCP Apps Client
 *
 * Runs inside the MCP Apps iframe. Receives response action data from the
 * server-side tool via `ontoolresult` and renders an interactive dashboard
 * with tabbed navigation, action cards, playbooks, and action history.
 */

import { App } from '@modelcontextprotocol/ext-apps';

// ───── Types ─────────────────────────────────────────────

interface ResponseAction {
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

interface PlaybookStep {
  action: string;
  tool: string;
  status?: string;
}

interface Playbook {
  name: string;
  icon: string;
  trigger: string;
  steps: PlaybookStep[];
}

interface ResponseData {
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

// ───── DOM Refs ──────────────────────────────────────────
const loading = document.getElementById('loading')!;
const tabBar = document.getElementById('tabBar')!;
const reportDateEl = document.getElementById('reportDate')!;
const titleEl = document.getElementById('title')!;
const footerStatus = document.getElementById('footerStatus')!;
const footerTimestamp = document.getElementById('footerTimestamp')!;
const totalActionsEl = document.getElementById('totalActions')!;
const openReportBtn = document.getElementById('openReportBtn') as HTMLButtonElement;

// ───── State ─────────────────────────────────────────────
let responseData: ResponseData | null = null;
let currentHistoryFilter = 'all';
let reportFileUri: string | null = null;

// ───── Init MCP App ──────────────────────────────────────
const app = new App({
  name: 'CyberProbe Response Actions',
  version: '2.0.0',
});

app.onthemechange = (theme) => {
  document.documentElement.setAttribute('data-theme', theme.mode);
};

async function requestFullscreen() {
  try {
    const ctx = (app as any).getHostContext?.();
    if (ctx?.requestDisplayMode) {
      await ctx.requestDisplayMode('fullscreen');
    } else {
      await (app as any).requestDisplayMode?.('fullscreen');
    }
  } catch { /* ignore */ }
}

app.ontoolresult = (result: any) => {
  const data = result?._meta?.responseData as ResponseData | undefined;
  reportFileUri = result?._meta?.reportPath || null;

  if (!data || !data.actions) {
    loading.innerHTML = `<div class="empty-state"><div class="icon">🛡️</div><div>No response action data received</div></div>`;
    return;
  }

  responseData = data;
  loading.style.display = 'none';

  // Update header
  titleEl.textContent = data.title || 'Response Actions Console';
  reportDateEl.textContent = data.reportDate || new Date().toISOString().slice(0, 10);
  totalActionsEl.textContent = `${data.actions.length} actions`;
  footerTimestamp.textContent = new Date().toLocaleTimeString();

  if (reportFileUri) {
    openReportBtn.style.display = 'inline-block';
    openReportBtn.onclick = () => app.openLink?.(reportFileUri!);
  }

  // Show first tab
  document.getElementById('panel-overview')!.classList.add('active');

  renderOverview(data);
  renderDeviceActions(data);
  renderIdentityActions(data);
  renderIncidentActions(data);
  renderForensicActions(data);
  renderPlaybooks(data);
  renderHistory(data);
  footerStatus.textContent = `${data.actions.length} actions loaded`;

  app.sendSizeChanged?.();
};

app.connect();
requestFullscreen();

// ───── Tab Navigation ────────────────────────────────────
tabBar.addEventListener('click', (e) => {
  const tab = (e.target as HTMLElement).closest('.tab');
  if (!tab) return;
  const tabName = tab.getAttribute('data-tab')!;

  tabBar.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  tab.classList.add('active');

  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.getElementById(`panel-${tabName}`)?.classList.add('active');

  app.sendSizeChanged?.();
});

// ───── Render Functions ──────────────────────────────────

function statusDot(status: string): string {
  const s = status.toLowerCase();
  const cls = s === 'succeeded' ? 'succeeded' : s === 'pending' || s === 'planned' ? 'pending' : s === 'inprogress' ? 'inprogress' : s === 'failed' ? 'failed' : 'cancelled';
  return `<span class="status-dot ${cls}"></span>${status}`;
}

function severityBadge(status: string): string {
  const s = status.toLowerCase();
  if (s === 'succeeded') return `<span class="badge badge-success">${statusDot(status)}</span>`;
  if (s === 'pending' || s === 'planned') return `<span class="badge badge-pending">${statusDot(status)}</span>`;
  if (s === 'inprogress') return `<span class="badge badge-info">${statusDot(status)}</span>`;
  if (s === 'failed') return `<span class="badge badge-critical">${statusDot(status)}</span>`;
  return `<span class="badge badge-info">${statusDot(status)}</span>`;
}

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

function renderActionCard(action: ResponseAction): string {
  const time = action.timestamp ? new Date(action.timestamp).toLocaleString() : '';
  const detailsHtml = action.details
    ? Object.entries(action.details).map(([k, v]) => `<span style="margin-right:8px;"><strong>${k}:</strong> ${v}</span>`).join('')
    : '';

  return `
    <div class="action-card">
      <div class="action-header">
        <span class="action-title">${actionIcon(action.action)} ${action.action}</span>
        ${severityBadge(action.status)}
      </div>
      <div class="action-desc">${action.comment || ''}</div>
      <div class="action-target">${action.target}</div>
      ${detailsHtml ? `<div style="margin-top:6px;font-size:10px;color:var(--text-muted);">${detailsHtml}</div>` : ''}
      <div class="action-footer">
        <span class="action-time">${time}</span>
        ${action.requestor ? `<span style="font-size:10px;color:var(--text-muted);">by ${action.requestor}</span>` : ''}
      </div>
    </div>`;
}

function renderOverview(data: ResponseData) {
  const s = data.summary || computeSummary(data.actions);
  const statsEl = document.getElementById('overviewStats')!;
  statsEl.innerHTML = `
    <div class="stat-card info"><div class="stat-value">${s.totalActions}</div><div class="stat-label">Total Actions</div></div>
    <div class="stat-card success"><div class="stat-value">${s.succeeded}</div><div class="stat-label">Succeeded</div></div>
    <div class="stat-card purple"><div class="stat-value">${s.pending + s.inProgress}</div><div class="stat-label">Pending</div></div>
    <div class="stat-card critical"><div class="stat-value">${s.failed}</div><div class="stat-label">Failed</div></div>
    <div class="stat-card warning"><div class="stat-value">${s.devicesIsolated}</div><div class="stat-label">Devices Isolated</div></div>
    <div class="stat-card critical"><div class="stat-value">${s.usersDisabled}</div><div class="stat-label">Users Disabled</div></div>
  `;

  const recentEl = document.getElementById('recentActions')!;
  const recentActions = [...data.actions].sort((a, b) => {
    const ta = a.timestamp ? new Date(a.timestamp).getTime() : 0;
    const tb = b.timestamp ? new Date(b.timestamp).getTime() : 0;
    return tb - ta;
  }).slice(0, 6);
  recentEl.innerHTML = `<div class="action-grid">${recentActions.map(renderActionCard).join('')}</div>`;
}

function renderDeviceActions(data: ResponseData) {
  const actions = data.actions.filter(a => a.type === 'device');
  const container = document.getElementById('deviceActions')!;
  const filters = document.getElementById('deviceFilters')!;

  if (actions.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="icon">🖥️</div><div>No device response actions</div></div>';
    return;
  }

  const actionTypes = [...new Set(actions.map(a => a.action))];
  filters.innerHTML = `
    <div class="filter-chip active" data-dtype="all">All (${actions.length})</div>
    ${actionTypes.map(t => `<div class="filter-chip" data-dtype="${t}">${t} (${actions.filter(a => a.action === t).length})</div>`).join('')}
  `;

  filters.addEventListener('click', (e) => {
    const chip = (e.target as HTMLElement).closest('.filter-chip') as HTMLElement;
    if (!chip) return;
    filters.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    const dtype = chip.getAttribute('data-dtype')!;
    const filtered = dtype === 'all' ? actions : actions.filter(a => a.action === dtype);
    container.innerHTML = `<div class="action-grid">${filtered.map(renderActionCard).join('')}</div>`;
  });

  container.innerHTML = `<div class="action-grid">${actions.map(renderActionCard).join('')}</div>`;
}

function renderIdentityActions(data: ResponseData) {
  const actions = data.actions.filter(a => a.type === 'identity');
  const container = document.getElementById('identityActions')!;
  if (actions.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="icon">👤</div><div>No identity response actions</div></div>';
    return;
  }
  container.innerHTML = `<div class="action-grid">${actions.map(renderActionCard).join('')}</div>`;
}

function renderIncidentActions(data: ResponseData) {
  const actions = data.actions.filter(a => a.type === 'incident');
  const container = document.getElementById('incidentActions')!;
  if (actions.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="icon">📝</div><div>No incident management actions</div></div>';
    return;
  }
  container.innerHTML = `<div class="action-grid">${actions.map(renderActionCard).join('')}</div>`;
}

function renderForensicActions(data: ResponseData) {
  const actions = data.actions.filter(a => a.type === 'forensic');
  const container = document.getElementById('forensicActions')!;
  if (actions.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="icon">🔬</div><div>No forensic collections</div></div>';
    return;
  }
  container.innerHTML = `<div class="action-grid">${actions.map(renderActionCard).join('')}</div>`;
}

function renderPlaybooks(data: ResponseData) {
  const container = document.getElementById('playbookList')!;
  const playbooks: Playbook[] = data.playbooks || defaultPlaybooks();

  container.innerHTML = playbooks.map(pb => `
    <div class="playbook-card">
      <div class="playbook-header" onclick="this.parentElement.classList.toggle('expanded')">
        <span class="playbook-title">${pb.icon} ${pb.name}</span>
        <span class="chevron">▶</span>
      </div>
      <div class="playbook-steps">
        <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;">Trigger: ${pb.trigger}</div>
        ${pb.steps.map((s, i) => `
          <div class="playbook-step">
            <div class="step-number">${i + 1}</div>
            <div class="step-content">
              <div class="step-action">${s.action}</div>
              <div class="step-tool">${s.tool}</div>
            </div>
            ${s.status ? severityBadge(s.status) : ''}
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');
}

function renderHistory(data: ResponseData) {
  const tbody = document.getElementById('historyBody')!;
  const searchInput = document.getElementById('historySearch') as HTMLInputElement;
  const filterContainer = document.getElementById('panel-history')!.querySelector('.filter-bar')!;

  function renderRows(filter: string, search: string) {
    let actions = [...data.actions];
    if (filter !== 'all') actions = actions.filter(a => a.status === filter);
    if (search) {
      const s = search.toLowerCase();
      actions = actions.filter(a =>
        a.action.toLowerCase().includes(s) ||
        a.target.toLowerCase().includes(s) ||
        (a.comment || '').toLowerCase().includes(s)
      );
    }
    actions.sort((a, b) => {
      const ta = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const tb = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      return tb - ta;
    });

    tbody.innerHTML = actions.length === 0
      ? `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:20px;">No matching actions</td></tr>`
      : actions.map(a => `
        <tr>
          <td>${a.timestamp ? new Date(a.timestamp).toLocaleString() : '—'}</td>
          <td>${actionIcon(a.action)} ${a.action}</td>
          <td style="font-family:monospace;font-size:11px;">${a.target}</td>
          <td>${severityBadge(a.status)}</td>
          <td>${a.requestor || '—'}</td>
        </tr>
      `).join('');
  }

  filterContainer.addEventListener('click', (e) => {
    const chip = (e.target as HTMLElement).closest('.filter-chip') as HTMLElement;
    if (!chip) return;
    filterContainer.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    currentHistoryFilter = chip.getAttribute('data-filter')!;
    renderRows(currentHistoryFilter, searchInput.value);
  });

  searchInput.addEventListener('input', () => {
    renderRows(currentHistoryFilter, searchInput.value);
  });

  renderRows('all', '');
}

// ───── Helpers ───────────────────────────────────────────

function computeSummary(actions: ResponseAction[]) {
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

function defaultPlaybooks(): Playbook[] {
  return [
    {
      name: 'Compromised User Account',
      icon: '🔐',
      trigger: 'Account compromise confirmed (suspicious sign-ins, impossible travel, credential leak)',
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
      trigger: 'Active malware detected on endpoint (AV alert, suspicious process, C2 communication)',
      steps: [
        { action: 'Isolate device immediately', tool: 'defender_isolate_device' },
        { action: 'Stop and quarantine malware', tool: 'defender_stop_and_quarantine' },
        { action: 'Restrict code execution', tool: 'defender_restrict_code_execution' },
        { action: 'Run full AV scan', tool: 'defender_run_antivirus_scan' },
        { action: 'Collect forensic package', tool: 'defender_collect_investigation_package' },
        { action: 'Check file spread', tool: 'GetDefenderFileRelatedMachines' },
        { action: 'Document and classify', tool: 'defender_add_incident_comment' },
      ],
    },
    {
      name: 'Ransomware / Bulk Containment',
      icon: '🚨',
      trigger: 'Multiple devices compromised, lateral movement detected, ransomware spreading',
      steps: [
        { action: 'Bulk isolate all affected devices', tool: 'defender_isolate_multiple' },
        { action: 'Disable all affected user accounts', tool: 'defender_disable_ad_account (×N)' },
        { action: 'Restrict code execution on all', tool: 'defender_restrict_code_execution (×N)' },
        { action: 'Run AV scans on all devices', tool: 'defender_run_antivirus_scan (×N)' },
        { action: 'Collect forensics from patient zero', tool: 'defender_collect_investigation_package' },
        { action: 'Tag incident as critical', tool: 'defender_add_incident_tags' },
        { action: 'Assign to incident commander', tool: 'defender_assign_incident' },
      ],
    },
    {
      name: 'Post-Remediation Recovery',
      icon: '🔄',
      trigger: 'Threat eradicated, ready to restore operations',
      steps: [
        { action: 'Verify AV scan results', tool: 'defender_get_machine_actions' },
        { action: 'Release device from isolation', tool: 'defender_release_device' },
        { action: 'Re-enable user account', tool: 'defender_enable_ad_account' },
        { action: 'Confirm user safe', tool: 'defender_confirm_user_safe' },
        { action: 'Resolve incident', tool: 'defender_update_incident_status' },
        { action: 'Add closing comment', tool: 'defender_add_incident_comment' },
      ],
    },
  ];
}
