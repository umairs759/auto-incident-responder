/**
 * MITRE ATT&CK Matrix Dynamic Visualization Engine.
 * Classifies tactics, maps techniques, and triggers live glowing indicators
 * upon receiving correlated telemetry alerts from the active daemon.
 */

const MITRE_FRAMEWORK = {
  "Execution": [
    { id: "T1059.004", name: "Unix Shell Spawn", hits: 0, active: false }
  ],
  "Privilege Escalation": [
    { id: "T1548.001", name: "Setuid / Gid Abuse", hits: 0, active: false }
  ],
  "Discovery": [
    { id: "T1046", name: "Network Service Discovery", hits: 0, active: false }
  ],
  "Command & Control": [
    { id: "T1071.001", name: "Web Protocols C2", hits: 0, active: false }
  ],
  "Impact": [
    { id: "T1486", name: "Data Encrypted for Impact", hits: 0, active: false }
  ]
};

function renderMitreMatrix() {
  const container = document.getElementById("mitre-matrix-grid");
  if (!container) return;
  container.innerHTML = "";

  Object.entries(MITRE_FRAMEWORK).forEach(([tactic, techniques]) => {
    const col = document.createElement("div");
    col.className = "flex flex-col gap-2";

    const header = document.createElement("div");
    header.className = "text-[11px] font-bold uppercase tracking-wider text-slate-400 bg-slate-900/90 border border-slate-800 p-2.5 rounded text-center";
    header.innerText = tactic;
    col.appendChild(header);

    techniques.forEach((tech) => {
      const card = document.createElement("div");
      const safeId = tech.id.replace(".", "_");
      card.id = `mitre-${safeId}`;
      card.className = `text-xs p-3 rounded border transition-all duration-300 relative ${
        tech.active
          ? "bg-red-950/60 border-red-500 text-red-100 critical-threat-border"
          : "bg-slate-900/40 border-slate-800/80 text-slate-400"
      }`;

      card.innerHTML = `
        <div class="flex justify-between items-start mb-1">
          <span class="mono font-bold text-[11px] text-yellow-400">${tech.id}</span>
          ${
            tech.hits > 0
              ? `<span class="bg-red-600 text-white font-bold text-[10px] px-1.5 py-0.2 rounded-full font-mono">${tech.hits}</span>`
              : ""
          }
        </div>
        <div class="font-medium text-[11px] leading-tight text-slate-200">${tech.name}</div>
      `;
      col.appendChild(card);
    });

    container.appendChild(col);
  });
}

function recordMitreHit(techniqueId) {
  let updated = false;
  Object.values(MITRE_FRAMEWORK).forEach((techniqueList) => {
    techniqueList.forEach((tech) => {
      if (tech.id === techniqueId) {
        tech.active = true;
        tech.hits += 1;
        updated = true;
      }
    });
  });

  if (updated) {
    renderMitreMatrix();
  }
}