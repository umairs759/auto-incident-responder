/**
 * app.js
 * SecOps Command Center controller — WebSocket + REST with local fallback loop.
 */

let socket = null;
let threatCounter = 0;
let containmentCounter = 0;
const alertCache = new Map();

let reconnectDelay = 1000;
const RECONNECT_MAX_MS = 30000;

let usingFallback = false;
let fallbackStatsTimer = null;
let fallbackAlertTimer = null;
let pidCount = 140 + Math.floor(Math.random() * 60);

let audioEnabled = true;
let audioCtx = null;
let currentFilter = 'all';

const SEVERITY_STYLES = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-yellow-400',
  LOW: 'text-slate-400',
};

const DEMO_SCENARIOS = [
  {
    target_process_name: 'gunicorn \u2192 /bin/bash',
    target_pid: 4118,
    description: 'Non-interactive worker spawned an interactive shell',
    mitre_technique_id: 'T1059.004',
    severity: 'CRITICAL',
    action_taken: 'SIGKILL (AUTO)',
    forensic_data: {
      parent_cmd: 'gunicorn: worker [app:wsgi]',
      child_cmd: '/bin/bash -i',
      user: 'www-data',
      mitigation: { success: true, note: 'SIGSTOP at t+2ms, dump captured, SIGKILL at t+11ms' },
    },
  },
  {
    target_process_name: 'bash \u2192 canary encryptor',
    target_pid: 4290,
    description: 'SHA-256 drift on /tmp/.edr_canaries/customer_database_export.sql',
    mitre_technique_id: 'T1486',
    severity: 'CRITICAL',
    action_taken: 'SIGKILL (AUTO)',
    forensic_data: {
      canary_file: 'customer_database_export.sql',
      hash_before: 'a13f...9e02',
      hash_after: '7cd8...41bb',
      mitigation: { success: true, note: 'Process tree frozen, snapshot written, SIGKILL dispatched' },
    },
  },
  {
    target_process_name: 'node \u2192 remote C2 socket',
    target_pid: 4602,
    description: 'Established outbound connection from reverse-shell child of node process',
    mitre_technique_id: 'T1071.001',
    severity: 'HIGH',
    action_taken: 'NETWORK ISOLATED',
    forensic_data: {
      remote_ip: '185.220.101.47',
      remote_port: 4444,
      mitigation: { success: true, note: 'iptables INPUT/OUTPUT DROP injected, socket severed' },
    },
  },
];

function initializeWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;

  try {
    socket = new WebSocket(wsUrl);
  } catch (err) {
    startFallback();
    return;
  }

  const connectTimeout = setTimeout(() => {
    if (socket && socket.readyState !== WebSocket.OPEN) socket.close();
  }, 3000);

  socket.onopen = () => {
    clearTimeout(connectTimeout);
    stopFallback();
    reconnectDelay = 1000;
    setStreamStatus('online');
  };

  socket.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      const evt = (payload.type || payload.event || payload.action || '').toLowerCase();
      const data = payload.data || payload.alert || payload.metrics || payload;

      if (evt.includes('heartbeat') || evt.includes('telemetry') || payload.cpu_percent !== undefined) {
        handleHeartbeat(payload.agent_id || 'Linux-Host', data);
      } else if (evt.includes('alert') || evt.includes('threat') || payload.mitre_technique_id || (data && data.mitre_technique_id)) {
        handleIncomingAlert(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  socket.onclose = () => {
    clearTimeout(connectTimeout);
    setStreamStatus('offline');
    startFallback();
    setTimeout(() => {
      reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_MS);
      initializeWebSocket();
    }, reconnectDelay);
  };

  socket.onerror = () => {
    if (socket) socket.close();
  };
}

function setStreamStatus(state) {
  const badge = document.getElementById('stream-badge');
  const statusElem = document.getElementById('endpoint-status');
  if (!badge || !statusElem) return;

  if (state === 'online') {
    badge.className = 'px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-semibold text-[11px]';
    badge.textContent = 'STREAM ONLINE';
    statusElem.textContent = 'ONLINE';
    statusElem.className = 'text-emerald-400 font-semibold';
  } else {
    badge.className = 'px-2.5 py-1 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400 font-semibold text-[11px]';
    badge.textContent = 'DEMO MODE';
    statusElem.textContent = 'OFFLINE';
    statusElem.className = 'text-amber-400 font-semibold';
  }
}

async function syncEndpointStatus() {
  try {
    const res = await fetch('/api/endpoints');
    if (res.ok) {
      const endpoints = await res.json();
      if (Array.isArray(endpoints) && endpoints.length > 0) {
        handleHeartbeat(endpoints[0].agent_id || endpoints[0].hostname, endpoints[0]);
      }
    }
  } catch (e) {}

  try {
    const aRes = await fetch('/api/alerts?limit=50');
    if (aRes.ok) {
      const alerts = await aRes.json();
      if (Array.isArray(alerts)) alerts.forEach(handleIncomingAlert);
    }
  } catch (e) {}
}

function startFallback() {
  if (usingFallback) return;
  usingFallback = true;
  setStreamStatus('offline');

  fallbackStatsTimer = setInterval(() => {
    handleHeartbeat('demo-host', {
      cpu_percent: Math.random() * 1.4 + 0.2,
      memory_percent: Math.random() * 6 + 8,
      active_pids_count: (pidCount += Math.floor(Math.random() * 5) - 2),
    });
  }, 2000);

  fallbackAlertTimer = setInterval(() => {
    if (Math.random() < 0.35) {
      const scenario = DEMO_SCENARIOS[Math.floor(Math.random() * DEMO_SCENARIOS.length)];
      handleIncomingAlert({ ...scenario, alert_id: `demo-${Date.now()}`, timestamp: Date.now() });
    }
  }, 9000);
}

function stopFallback() {
  usingFallback = false;
  clearInterval(fallbackStatsTimer);
  clearInterval(fallbackAlertTimer);
  fallbackStatsTimer = null;
  fallbackAlertTimer = null;
}

function handleHeartbeat(agentId, metrics) {
  if (!metrics) return;
  const cpu = document.getElementById('stat-cpu');
  if (cpu && metrics.cpu_percent !== undefined) cpu.innerText = `${Number(metrics.cpu_percent).toFixed(1)}%`;

  const mem = document.getElementById('stat-mem');
  if (mem && metrics.memory_percent !== undefined) mem.innerText = `${Number(metrics.memory_percent).toFixed(1)}%`;

  const pids = document.getElementById('stat-pids');
  if (pids && (metrics.active_pids_count !== undefined || metrics.pids_count !== undefined)) {
    pids.innerText = metrics.active_pids_count || metrics.pids_count;
  }
}

function handleIncomingAlert(alert) {
  if (!alert) return;
  const alertId = alert.alert_id || `alert-${Date.now()}`;
  if (alertCache.has(alertId)) return;
  alertCache.set(alertId, alert);

  threatCounter++;
  const st = document.getElementById('stat-threats');
  if (st) st.innerText = threatCounter;

  const isMitigated = alert.forensic_data?.mitigation?.success ?? alert.is_contained !== false;
  if (isMitigated) {
    containmentCounter++;
    const sc = document.getElementById('stat-contained');
    if (sc) sc.innerText = containmentCounter;
  }

  const techId = alert.mitre_technique_id || alert.technique_id;
  if (techId && typeof recordMitreHit === 'function') recordMitreHit(techId);

  const severity = (alert.severity || 'CRITICAL').toUpperCase();
  const actionTaken = alert.action_taken || alert.status || (isMitigated ? 'SIGKILL (AUTO)' : 'LOGGED');

  if (severity === 'CRITICAL' || severity === 'HIGH') playAlarm();

  const tableBody = document.getElementById('alerts-table-body');
  if (!tableBody) return;

  const row = document.createElement('tr');
  row.className = 'border-b border-white/[0.06] hover:bg-[#1b202c] text-xs transition-colors';
  row.setAttribute('data-alert-id', alertId);
  row.setAttribute('data-severity', severity.toLowerCase());
  row.setAttribute('data-mitigated', isMitigated ? 'true' : 'false');

  const timeVal = alert.timestamp ? (alert.timestamp > 1e11 ? alert.timestamp : alert.timestamp * 1000) : Date.now();
  const dateStr = new Date(timeVal).toLocaleTimeString();
  const sevClass = SEVERITY_STYLES[severity] || SEVERITY_STYLES.LOW;
  const actionClass = isMitigated ? 'bg-emerald-950/80 border-emerald-700 text-emerald-300' : 'bg-slate-800/80 border-slate-600 text-slate-300';

  row.innerHTML = `
    <td class="p-3 font-mono text-slate-400">${dateStr}</td>
    <td class="p-3"><span class="${sevClass} font-bold">[${escapeHtml(severity)}]</span></td>
    <td class="p-3 font-mono text-slate-200">
      ${escapeHtml(alert.target_process_name || alert.process_name || 'bash')}
      <span class="text-slate-500 text-[11px]">(${escapeHtml(alert.target_pid || alert.pid || 0)})</span>
    </td>
    <td class="p-3 text-slate-300 max-w-sm truncate" title="${escapeHtml(alert.description || '')}">
      ${escapeHtml(alert.description || 'Interactive shell spawn anomaly detected')}
    </td>
    <td class="p-3 font-mono text-yellow-400 font-bold">${escapeHtml(techId || 'T1059.004')}</td>
    <td class="p-3">
      <span class="px-2 py-0.5 rounded border text-[10px] font-semibold font-mono ${actionClass}">
        ${escapeHtml(actionTaken)}
      </span>
    </td>
    <td class="p-3 text-right">
      <button onclick="inspectForensics('${alertId}')" class="btn-primary text-[10px] py-1">
        FORENSICS
      </button>
    </td>
  `;

  tableBody.insertBefore(row, tableBody.firstChild);
  applyCurrentFilter();

  const ticker = document.getElementById('telemetry-ticker-text');
  if (ticker) ticker.textContent = `\u26a0 ${severity} \u2014 ${alert.description || techId || 'anomaly detected'}`;
}

function filterTable(filter) {
  currentFilter = filter;
  document.querySelectorAll('.filter-pill').forEach(btn => {
    btn.classList.remove('active');
    if (btn.innerText.toLowerCase().includes(filter) || (filter === 'mitigated' && btn.innerText.includes('AUTO'))) {
      btn.classList.add('active');
    }
  });
  applyCurrentFilter();
}

function applyCurrentFilter() {
  const rows = document.querySelectorAll('#alerts-table-body tr');
  rows.forEach(r => {
    const sev = r.getAttribute('data-severity');
    const mit = r.getAttribute('data-mitigated') === 'true';
    if (currentFilter === 'all') {
      r.style.display = '';
    } else if (currentFilter === 'critical' && sev === 'critical') {
      r.style.display = '';
    } else if (currentFilter === 'mitigated' && mit) {
      r.style.display = '';
    } else {
      r.style.display = 'none';
    }
  });
}

function inspectForensics(alertId) {
  const alert = alertCache.get(alertId);
  if (!alert) return;

  const modal = document.getElementById('forensics-modal');
  const viewer = document.getElementById('forensic-json-viewer');
  if (viewer && modal) {
    viewer.innerText = JSON.stringify(alert.forensic_data || alert, null, 2);
    modal.classList.remove('hidden');
  }
}

function closeForensicModal() {
  const modal = document.getElementById('forensics-modal');
  if (modal) modal.classList.add('hidden');
}

function copyForensicsToClipboard() {
  const viewer = document.getElementById('forensic-json-viewer');
  if (viewer) {
    navigator.clipboard.writeText(viewer.innerText);
    alert('Forensic JSON artifact copied to clipboard.');
  }
}

function escapeHtml(str) {
  if (str === undefined || str === null) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function ensureAudioCtx() {
  if (!audioCtx) {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (AC) audioCtx = new AC();
  }
  return audioCtx;
}

function playAlarm() {
  if (!audioEnabled) return;
  const ctx = ensureAudioCtx();
  if (!ctx) return;

  const now = ctx.currentTime;
  [880, 660].forEach((freq, i) => {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'square';
    osc.frequency.setValueAtTime(freq, now + i * 0.16);
    gain.gain.setValueAtTime(0.0001, now + i * 0.16);
    gain.gain.exponentialRampToValueAtTime(0.06, now + i * 0.16 + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + i * 0.16 + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + i * 0.16 + 0.14);
    osc.connect(gain).connect(ctx.destination);
    osc.start(now + i * 0.16);
    osc.stop(now + i * 0.16 + 0.15);
  });
}

function toggleAudioFX() {
  audioEnabled = !audioEnabled;
  const icon = document.getElementById('sound-icon');
  const text = document.getElementById('sound-text');
  if (text) text.textContent = audioEnabled ? 'AUDIO ON' : 'AUDIO OFF';
  if (icon) icon.textContent = audioEnabled ? '\ud83d\udd0a' : '\ud83d\udd07';
  if (audioEnabled) ensureAudioCtx();
}

function triggerSimulatedAttack() {
  const scenario = DEMO_SCENARIOS[Math.floor(Math.random() * DEMO_SCENARIOS.length)];
  handleIncomingAlert({ ...scenario, alert_id: `manual-${Date.now()}`, timestamp: Date.now() });

  if (socket && socket.readyState === WebSocket.OPEN) {
    try {
      socket.send(JSON.stringify({ type: 'trigger_simulation' }));
    } catch (err) {}
  }
}

window.addEventListener('DOMContentLoaded', () => {
  if (typeof renderMitreMatrix === 'function') renderMitreMatrix();
  initializeWebSocket();
  syncEndpointStatus();
  setInterval(syncEndpointStatus, 3000);
});

window.triggerSimulatedAttack = triggerSimulatedAttack;
window.toggleAudioFX = toggleAudioFX;
window.closeForensicModal = closeForensicModal;
window.inspectForensics = inspectForensics;
window.filterTable = filterTable;
window.copyForensicsToClipboard = copyForensicsToClipboard;