"""
agent/detector.py
Rule engine that consumes Collector snapshots and emits Alert objects,
each explicitly mapped to MITRE ATT&CK tactics/techniques.

Rules implemented:
  R1 - Interactive shell spawned by a non-interactive server binary
       (Reverse Shell) -> T1059.004, T1071.001
  R2 - Shell process holding an established connection to a known
       reverse-shell port or unusual high port -> T1071.001
  R3 - Single PID contacting many distinct destination ports in a short
       window (Network Service Scanning) -> T1046
  R4 - Canary/FIM: rapid multi-file modification of sensitive paths
       (Ransomware behavior) -> T1486, T1489
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, List, Optional, Tuple

from .collector import Snapshot, ProcessRecord
from .config import DetectionPolicy

logger = logging.getLogger("edr.detector")


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    pid: Optional[int]
    ppid: Optional[int]
    process_name: Optional[str]
    cmdline: Optional[List[str]]
    raddr: Optional[Tuple[str, int]]
    timestamp: float = field(default_factory=time.time)
    requires_containment: bool = True


class Detector:
    def __init__(self, policy: DetectionPolicy) -> None:
        self.policy = policy
        self._alert_seq = 0

        # Rule state: PID -> deque[(timestamp, dest_port)] for scan detection
        self._port_touch_history: Dict[int, Deque[Tuple[float, int]]] = defaultdict(deque)

        # Canary FIM state: path -> last known sha256
        self._canary_hashes: Dict[str, str] = {}
        # Rolling window of (timestamp, path) modification events
        self._canary_mod_events: Deque[Tuple[float, str]] = deque()

        self._already_alerted_pids: set[int] = set()

    def _next_alert_id(self) -> str:
        self._alert_seq += 1
        return f"AL-{int(time.time())}-{self._alert_seq:05d}"

    # ---------- R1: Reverse shell parent/child anomaly ----------
    def _check_shell_spawn(self, snapshot: Snapshot) -> List[Alert]:
        alerts: List[Alert] = []
        for pid, proc in snapshot.processes.items():
            if pid in self._already_alerted_pids:
                continue
            proc_basename = os.path.basename(proc.name or "")
            if proc_basename not in self.policy.shell_binaries:
                continue

            parent = snapshot.processes.get(proc.ppid)
            if parent is None:
                continue
            parent_basename = os.path.basename(parent.name or parent.exe or "")

            if parent_basename in self.policy.suspicious_parent_binaries:
                self._already_alerted_pids.add(pid)
                alerts.append(
                    Alert(
                        alert_id=self._next_alert_id(),
                        rule_id="R1_REVERSE_SHELL_SPAWN",
                        severity=Severity.CRITICAL,
                        title=f"Interactive shell spawned by {parent_basename}",
                        description=(
                            f"Process '{parent_basename}' (pid={parent.pid}) spawned "
                            f"interactive shell '{proc_basename}' (pid={pid}). "
                            f"Non-interactive service binaries should never spawn a shell; "
                            f"this is a strong reverse-shell indicator."
                        ),
                        mitre_tactic="Execution",
                        mitre_technique_id="T1059.004",
                        mitre_technique_name="Command and Scripting Interpreter: Unix Shell",
                        pid=pid,
                        ppid=proc.ppid,
                        process_name=proc_basename,
                        cmdline=proc.cmdline,
                        raddr=None,
                    )
                )
        return alerts

    # ---------- R2: Shell with C2-like outbound connection ----------
    def _check_shell_c2_connection(self, snapshot: Snapshot) -> List[Alert]:
        alerts: List[Alert] = []
        shell_pids = {
            pid for pid, p in snapshot.processes.items()
            if os.path.basename(p.name or "") in self.policy.shell_binaries
        }
        for conn in snapshot.connections:
            if conn.pid not in shell_pids:
                continue
            if conn.status != "ESTABLISHED" or not conn.raddr_ip:
                continue
            if conn.raddr_ip in ("127.0.0.1", "::1"):
                continue

            flagged_port = conn.raddr_port in self.policy.reverse_shell_ports
            if not flagged_port:
                continue

            alert_key = conn.pid + 900000  # separate namespace from R1
            if alert_key in self._already_alerted_pids:
                continue
            self._already_alerted_pids.add(alert_key)

            proc = snapshot.processes.get(conn.pid)
            alerts.append(
                Alert(
                    alert_id=self._next_alert_id(),
                    rule_id="R2_SHELL_C2_CONNECTION",
                    severity=Severity.CRITICAL,
                    title=f"Shell process holds outbound C2-pattern connection",
                    description=(
                        f"Shell pid={conn.pid} has an ESTABLISHED connection to "
                        f"{conn.raddr_ip}:{conn.raddr_port}, matching known reverse-shell "
                        f"listener ports."
                    ),
                    mitre_tactic="Command and Control",
                    mitre_technique_id="T1071.001",
                    mitre_technique_name="Application Layer Protocol: Web Protocols",
                    pid=conn.pid,
                    ppid=proc.ppid if proc else None,
                    process_name=proc.name if proc else None,
                    cmdline=proc.cmdline if proc else None,
                    raddr=(conn.raddr_ip, conn.raddr_port),
                )
            )
        return alerts

    # ---------- R3: Port scan detection ----------
    def _check_port_scan(self, snapshot: Snapshot) -> List[Alert]:
        alerts: List[Alert] = []
        now = snapshot.timestamp
        window = self.policy.scan_window_secs

        touched_this_snapshot: Dict[int, set] = defaultdict(set)
        for conn in snapshot.connections:
            if conn.raddr_port:
                touched_this_snapshot[conn.pid].add(conn.raddr_port)

        for pid, ports in touched_this_snapshot.items():
            history = self._port_touch_history[pid]
            for port in ports:
                history.append((now, port))
            while history and now - history[0][0] > window:
                history.popleft()

            distinct_ports = {p for _, p in history}
            if len(distinct_ports) >= self.policy.port_scan_distinct_port_threshold:
                alert_key = pid + 800000
                if alert_key in self._already_alerted_pids:
                    continue
                self._already_alerted_pids.add(alert_key)

                proc = snapshot.processes.get(pid)
                alerts.append(
                    Alert(
                        alert_id=self._next_alert_id(),
                        rule_id="R3_PORT_SCAN",
                        severity=Severity.HIGH,
                        title="Network service scanning detected",
                        description=(
                            f"pid={pid} contacted {len(distinct_ports)} distinct ports "
                            f"within {window}s, consistent with active port scanning."
                        ),
                        mitre_tactic="Discovery",
                        mitre_technique_id="T1046",
                        mitre_technique_name="Network Service Scanning",
                        pid=pid,
                        ppid=proc.ppid if proc else None,
                        process_name=proc.name if proc else None,
                        cmdline=proc.cmdline if proc else None,
                        raddr=None,
                    )
                )
        return alerts

    # ---------- R4: Canary / ransomware FIM ----------
    @staticmethod
    def _sha256_of_file(path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (FileNotFoundError, PermissionError, IsADirectoryError):
            return None

    def _iter_canary_files(self) -> List[str]:
        files: List[str] = []
        for path in self.policy.canary_paths:
            if os.path.isdir(path):
                for root, _, names in os.walk(path):
                    for name in names:
                        files.append(os.path.join(root, name))
            elif os.path.isfile(path):
                files.append(path)
        return files

    def check_canary_integrity(self, now: Optional[float] = None) -> List[Alert]:
        """
        Called on its own cadence (canary_hash_interval_secs) from the agent
        loop, independent of process/network snapshots.
        """
        now = now or time.time()
        alerts: List[Alert] = []

        for path in self._iter_canary_files():
            current_hash = self._sha256_of_file(path)
            if current_hash is None:
                continue
            previous_hash = self._canary_hashes.get(path)
            self._canary_hashes[path] = current_hash

            if previous_hash is not None and previous_hash != current_hash:
                self._canary_mod_events.append((now, path))

        window = self.policy.canary_window_secs
        while self._canary_mod_events and now - self._canary_mod_events[0][0] > window:
            self._canary_mod_events.popleft()

        distinct_modified = {p for _, p in self._canary_mod_events}
        if len(distinct_modified) >= self.policy.canary_modification_threshold:
            alerts.append(
                Alert(
                    alert_id=self._next_alert_id(),
                    rule_id="R4_RANSOMWARE_CANARY",
                    severity=Severity.CRITICAL,
                    title="Mass modification of canary files detected",
                    description=(
                        f"{len(distinct_modified)} canary/sensitive files modified within "
                        f"{window}s: {sorted(distinct_modified)}. Pattern is consistent with "
                        f"ransomware encryption behavior."
                    ),
                    mitre_tactic="Impact",
                    mitre_technique_id="T1486",
                    mitre_technique_name="Data Encrypted for Impact",
                    pid=None,
                    ppid=None,
                    process_name=None,
                    cmdline=None,
                    raddr=None,
                    requires_containment=False,  # no single PID to contain; alert-only
                )
            )
            self._canary_mod_events.clear()

        return alerts

    def evaluate(self, snapshot: Snapshot) -> List[Alert]:
        alerts: List[Alert] = []
        alerts.extend(self._check_shell_spawn(snapshot))
        alerts.extend(self._check_shell_c2_connection(snapshot))
        alerts.extend(self._check_port_scan(snapshot))
        return alerts
