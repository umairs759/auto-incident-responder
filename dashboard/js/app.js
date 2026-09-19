/**
 * SecOps Command Center Engine.
 * Manages resilient WebSocket feeds, real-time alert triage,
 * forensic artifact inspections in modals, and operator-initiated manual containment.
 */

let socket = null;
let threatCounter = 0;
let containmentCounter = 0;
const alertCache = new Map();

function initializeWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/api/v1/ws/dashboard`;

  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    const badge = document.getElementById("stream-badge");
    badge.className = "px-2.5 py-1 rounded border text-[11px] font-bold bg-emerald-950 border-emerald-700 text-emerald-400";
    badge.innerText = "STREAM ONLINE";
  };

  socket.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.type === "NEW_ALERT") {
        handleIncomingAlert(payload.alert);
      } else if (payload.type === "HEARTBEAT_UPDATE") {
        handleHeartbeat(payload.agent_id, payload.metrics);
      } else if (payload.type === "ENDPOINT_STATUS_CHANGE") {
        if (payload.status === "OFFLINE") {
          const ep = document.getElementById("endpoint-status");
          ep.innerText = "DISCONNECTED";
          ep.className = "text-red-400 font-bold";
        }
      }
    } catch (err) {
      console.error("Payload processing error:", err);
    }
  };

  socket.onclose = () => {
    const badge = document.getElementById("stream-badge");
    badge.className = "px-2.5 py-1 rounded border text-[11px] font-bold bg-rose-950 border-rose-700 text-rose-400";
    badge.innerText = "RECONNECTING...";
    setTimeout(initializeWebSocket, 3000);
  };
}

function handleIncomingAlert(alert) {
  alertCache.set(alert.alert_id, alert);
  threatCounter++;
  document.getElementById("stat-threats").innerText = threatCounter;

  const isMitigated = alert.forensic_data?.mitigation?.success || alert.is_contained;
  if (isMitigated) {
    containmentCounter++;
    document.getElementById("stat-contained").innerText = containmentCounter;
  }

  if (alert.mitre_technique_id) {
    recordMitreHit(alert.mitre_technique_id);
  }

  const tableBody = document.getElementById("alerts-table-body");
  const row = document.createElement("tr");
  row.className = "border-b border-slate-800/80 hover:bg-slate-800/30 text-xs transition-colors";

  const dateStr = new Date(alert.timestamp * 1000).toLocaleTimeString();
  const severityBadge =
    alert.severity === "CRITICAL"
      ? '<span class="text-red-400 font-bold">[CRITICAL]</span>'
      : '<span class="text-amber-400 font-bold">[HIGH]</span>';

  row.innerHTML = `
    <td class="p-3 font-mono text-slate-400">${dateStr}</td>
    <td class="p-3">${severityBadge}</td>
    <td class="p-3 font-mono text-slate-200">
      ${escapeHtml(alert.target_process_name)}
      <span class="text-slate-500 text-[11px]">(${alert.target_pid})</span>
    </td>
    <td class="p-3 text-slate-300 max-w-sm truncate" title="${escapeHtml(alert.description)}">
      ${escapeHtml(alert.description)}
    </td>
    <td class="p-3 font-mono text-yellow-400 font-bold">${escapeHtml(alert.mitre_technique_id || "N/A")}</td>
    <td class="p-3">
      ${
        isMitigated
          ? '<span class="px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-700 text-emerald-300 text-[10px] font-semibold font-mono">SIGKILL (AUTO)</span>'
          : '<span class="px-2 py-0.5 rounded bg-amber-950/80 border border-amber-700 text-amber-300 text-[10px] font-semibold font-mono">UNMITIGATED</span>'
      }
    </td>
    <td class="p-3 text-right">
      <div class="flex items-center justify-end gap-2">
        <button onclick="inspectForensics('${alert.alert_id}')" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded text-[10px] font-mono text-slate-200 transition-colors">
          FORENSICS
        </button>
        <button onclick="triggerManualQuarantine('${alert.agent_id}', ${alert.target_pid}, '${alert.associated_ip || ""}')" class="px-2 py-1 bg-rose-950/60 hover:bg-rose-900 border border-rose-800 rounded text-[10px] font-mono text-rose-200 transition-colors">
          ISOLATE
        </button>
      </div>
    </td>
  `;

  tableBody.insertBefore(row, tableBody.firstChild);
}

function handleHeartbeat(agentId, metrics) {
  const statusElem = document.getElementById("endpoint-status");
  statusElem.innerText = "ONLINE";
  statusElem.className = "text-emerald-400 font-bold";

  document.getElementById("stat-cpu").innerText = `${metrics.cpu_percent.toFixed(1)}%`;
  document.getElementById("stat-mem").innerText = `${metrics.memory_percent.toFixed(1)}%`;
  document.getElementById("stat-pids").innerText = metrics.active_pids_count;
}

function inspectForensics(alertId) {
  const alert = alertCache.get(alertId);
  if (!alert) return;

  const modal = document.getElementById("forensics-modal");
  const viewer = document.getElementById("forensic-json-viewer");
  viewer.innerText = JSON.stringify(alert.forensic_data, null, 2);
  modal.classList.remove("hidden");
}

function closeForensicModal() {
  document.getElementById("forensics-modal").classList.add("hidden");
}

async function triggerManualQuarantine(agentId, pid, ip) {
  const proceed = confirm(`Dispatch manual containment sequence against PID ${pid}?`);
  if (!proceed) return;

  try {
    const res = await fetch("/api/v1/alerts/contain", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agent_id: agentId,
        target_pid: pid,
        associated_ip: ip || null,
        action_type: "PROCESS_SIGKILL",
      }),
    });
    const result = await res.json();
    alert(`Containment Outcome: ${result.message}`);
  } catch (err) {
    alert(`Manual Quarantine error: ${err.message}`);
  }
}

async function loadInitialIncidents() {
  try {
    const res = await fetch("/api/v1/alerts?limit=50");
    const incidents = await res.json();
    incidents.reverse().forEach(handleIncomingAlert);
  } catch (err) {
    console.error("Failed to load historical telemetry:", err);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

window.addEventListener("DOMContentLoaded", () => {
  renderMitreMatrix();
  loadInitialIncidents();
  initializeWebSocket();
});