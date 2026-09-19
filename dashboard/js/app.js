let socket = null;
let threatCounter = 0;
let containmentCounter = 0;
const alertCache = new Map();

function initializeWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;

  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    const badge = document.getElementById("stream-badge") || document.querySelector("div[class*='STREAM']");
    if (badge) {
      badge.className = "px-2.5 py-1 rounded border text-[11px] font-bold bg-emerald-950 border-emerald-700 text-emerald-400";
      badge.innerText = "STREAM ONLINE";
    }
  };

  socket.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      const evt = (payload.type || payload.event || payload.action || "").toLowerCase();
      const data = payload.data || payload.alert || payload.metrics || payload;

      if (evt.includes("heartbeat") || evt.includes("telemetry") || payload.cpu_percent !== undefined) {
        handleHeartbeat(payload.agent_id || "Linux-Host", data);
      } else if (evt.includes("alert") || evt.includes("threat") || payload.mitre_technique_id || (data && data.mitre_technique_id)) {
        handleIncomingAlert(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  socket.onclose = () => {
    setTimeout(initializeWebSocket, 2000);
  };
}

async function syncEndpointStatus() {
  try {
    const res = await fetch("/api/endpoints");
    if (res.ok) {
      const endpoints = await res.json();
      if (Array.isArray(endpoints) && endpoints.length > 0) {
        const ep = endpoints[0];
        handleHeartbeat(ep.agent_id || ep.hostname, ep);
      }
    }
  } catch (e) {
    // fallback
  }

  try {
    const aRes = await fetch("/api/alerts?limit=50");
    if (aRes.ok) {
      const alerts = await aRes.json();
      if (Array.isArray(alerts)) {
        alerts.forEach(handleIncomingAlert);
      }
    }
  } catch (e) {}
}

function handleHeartbeat(agentId, metrics) {
  if (!metrics) return;
  const statusElem = document.getElementById("endpoint-status");
  if (statusElem) {
    statusElem.innerText = "ONLINE";
    statusElem.className = "text-emerald-400 font-bold";
  }

  const cpu = document.getElementById("stat-cpu");
  if (cpu && metrics.cpu_percent !== undefined) cpu.innerText = `${Number(metrics.cpu_percent).toFixed(1)}%`;

  const mem = document.getElementById("stat-mem");
  if (mem && metrics.memory_percent !== undefined) mem.innerText = `${Number(metrics.memory_percent).toFixed(1)}%`;

  const pids = document.getElementById("stat-pids");
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
  const st = document.getElementById("stat-threats");
  if (st) st.innerText = threatCounter;

  const isMitigated = alert.forensic_data?.mitigation?.success || alert.is_contained !== false;
  if (isMitigated) {
    containmentCounter++;
    const sc = document.getElementById("stat-contained");
    if (sc) sc.innerText = containmentCounter;
  }

  const techId = alert.mitre_technique_id || alert.technique_id;
  if (techId && typeof recordMitreHit === "function") {
    recordMitreHit(techId);
  }

  const tableBody = document.getElementById("alerts-table-body");
  if (!tableBody) return;

  const row = document.createElement("tr");
  row.className = "border-b border-slate-800/80 hover:bg-slate-800/30 text-xs transition-colors";

  const timeVal = alert.timestamp ? (alert.timestamp > 1e11 ? alert.timestamp : alert.timestamp * 1000) : Date.now();
  const dateStr = new Date(timeVal).toLocaleTimeString();

  row.innerHTML = `
    <td class="p-3 font-mono text-slate-400">${dateStr}</td>
    <td class="p-3"><span class="text-red-400 font-bold">[CRITICAL]</span></td>
    <td class="p-3 font-mono text-slate-200">
      ${escapeHtml(alert.target_process_name || alert.process_name || "bash")}
      <span class="text-slate-500 text-[11px]">(${alert.target_pid || alert.pid || 0})</span>
    </td>
    <td class="p-3 text-slate-300 max-w-sm truncate" title="${escapeHtml(alert.description || "")}">
      ${escapeHtml(alert.description || "Interactive shell spawn anomaly detected")}
    </td>
    <td class="p-3 font-mono text-yellow-400 font-bold">${escapeHtml(techId || "T1059.004")}</td>
    <td class="p-3">
      <span class="px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-700 text-emerald-300 text-[10px] font-semibold font-mono">
        SIGKILL (AUTO)
      </span>
    </td>
    <td class="p-3 text-right">
      <button onclick="inspectForensics('${alertId}')" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded text-[10px] font-mono text-slate-200 transition-colors">
        FORENSICS
      </button>
    </td>
  `;

  tableBody.insertBefore(row, tableBody.firstChild);
}

function inspectForensics(alertId) {
  const alert = alertCache.get(alertId);
  if (!alert) return;

  const modal = document.getElementById("forensics-modal");
  const viewer = document.getElementById("forensic-json-viewer");
  if (viewer && modal) {
    viewer.innerText = JSON.stringify(alert.forensic_data || alert, null, 2);
    modal.classList.remove("hidden");
  }
}

function closeForensicModal() {
  const modal = document.getElementById("forensics-modal");
  if (modal) modal.classList.add("hidden");
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

window.addEventListener("DOMContentLoaded", () => {
  if (typeof renderMitreMatrix === "function") renderMitreMatrix();
  initializeWebSocket();
  syncEndpointStatus();
  setInterval(syncEndpointStatus, 3000);
});
