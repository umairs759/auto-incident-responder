/**
 * MITRE ATT&CK® (Enterprise Linux) tactical status board.
 * Includes dynamic decay glow timer to reflect real-time monitoring states.
 */

const MITRE_FRAMEWORK = {
  Execution: [
    { id: 'T1059.004', name: 'Unix Shell Spawn', hits: 0, active: false, timer: null },
  ],
  'Privilege Escalation': [
    { id: 'T1548.001', name: 'Setuid / Gid Abuse', hits: 0, active: false, timer: null },
  ],
  Discovery: [
    { id: 'T1046', name: 'Network Service Discovery', hits: 0, active: false, timer: null },
  ],
  'Command & Control': [
    { id: 'T1071.001', name: 'Web Protocols C2', hits: 0, active: false, timer: null },
  ],
  Impact: [
    { id: 'T1486', name: 'Data Encrypted for Impact', hits: 0, active: false, timer: null },
  ],
};

const ACTIVE_GLOW_MS = 4000;

function _escape(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function renderMitreMatrix() {
  const container = document.getElementById('mitre-matrix-grid');
  if (!container) return;
  container.innerHTML = '';

  Object.entries(MITRE_FRAMEWORK).forEach(([tactic, techniques]) => {
    const col = document.createElement('div');
    col.className = 'flex flex-col gap-2';

    const header = document.createElement('div');
    header.className =
      'text-[10px] font-bold uppercase tracking-wider text-slate-400 bg-[#0b0d11] border border-white/[0.08] p-2 rounded text-center mono';
    header.textContent = tactic;
    col.appendChild(header);

    techniques.forEach((tech) => {
      const card = document.createElement('div');
      const safeId = tech.id.replace('.', '_');
      card.id = `mitre-${safeId}`;
      card.className = `mitre-tile ${tech.active ? 'mitre-tile-active' : ''}`;
      card.title = tech.name;

      card.innerHTML = `
        <div class="flex justify-between items-start mb-1">
          <span class="mono font-bold text-[10px] ${tech.active ? 'text-rose-400' : 'text-slate-500'}">${_escape(tech.id)}</span>
          ${
            tech.hits > 0
              ? `<span class="mono text-[9px] px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-400 font-semibold">${tech.hits}\u00d7</span>`
              : ''
          }
        </div>
        <div class="text-[10px] font-medium text-slate-300 leading-tight">${_escape(tech.name)}</div>
      `;
      col.appendChild(card);
    });

    container.appendChild(col);
  });
}

function recordMitreHit(techniqueId) {
  let matched = null;

  Object.values(MITRE_FRAMEWORK).forEach((techniqueList) => {
    techniqueList.forEach((tech) => {
      if (tech.id === techniqueId) {
        tech.active = true;
        tech.hits += 1;
        matched = tech;
      }
    });
  });

  if (!matched) return;

  renderMitreMatrix();

  clearTimeout(matched.timer);
  matched.timer = setTimeout(() => {
    matched.active = false;
    renderMitreMatrix();
  }, ACTIVE_GLOW_MS);
}

window.MITRE_FRAMEWORK = MITRE_FRAMEWORK;
window.renderMitreMatrix = renderMitreMatrix;
window.recordMitreHit = recordMitreHit;