"""
agent/containment.py
Active Containment Engine: executes zero-human-latency response actions
when the Detector fires a CRITICAL/HIGH alert that requires containment.

Sequence for process-based threats:
  1. SIGSTOP the PID immediately (freeze, prevent further damage/cleanup)
  2. Capture full forensic snapshot (forensics.capture)
  3. Persist forensic artifact to disk
  4. SIGKILL the PID and any live children
  5. Inject a firewall rule to sever the remote IP (nftables/iptables)

All actions are logged and return a structured ContainmentResult so the
Shipper can report exactly what was done back to the SecOps dashboard.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Optional

import psutil

from . import forensics
from .config import ContainmentPolicy
from .detector import Alert

logger = logging.getLogger("edr.containment")


@dataclass
class ContainmentResult:
    alert_id: str
    pid: Optional[int]
    actions_taken: List[str] = field(default_factory=list)
    forensic_artifact_path: Optional[str] = None
    blocked_ip: Optional[str] = None
    success: bool = True
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class ContainmentEngine:
    def __init__(self, policy: ContainmentPolicy) -> None:
        self.policy = policy

    # ---------- Process containment ----------
    def _kill_process_tree(self, pid: int) -> List[int]:
        killed: List[int] = []
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                    killed.append(child.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            parent.kill()
            killed.append(pid)
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied as exc:
            logger.error("Access denied killing pid=%s: %s", pid, exc)
        return killed

    def _freeze(self, pid: int) -> bool:
        try:
            os.kill(pid, signal.SIGSTOP)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            logger.error("Permission denied sending SIGSTOP to pid=%s", pid)
            return False

    # ---------- Network containment ----------
    def _block_ip(self, ip: str) -> bool:
        """
        Injects a dynamic drop rule for the C2 IP. Uses nftables by default,
        falls back to iptables. Requires CAP_NET_ADMIN / root.
        """
        try:
            if self.policy.firewall_backend == "nftables":
                subprocess.run(
                    ["nft", "add", "table", "inet", "microedr"],
                    check=False, capture_output=True,
                )
                subprocess.run(
                    ["nft", "add", "chain", "inet", "microedr", "block",
                     "{", "type", "filter", "hook", "output", "priority", "0", ";", "}"],
                    check=False, capture_output=True,
                )
                result = subprocess.run(
                    ["nft", "add", "rule", "inet", "microedr", "block",
                     "ip", "daddr", ip, "drop"],
                    check=True, capture_output=True, text=True,
                )
            else:
                result = subprocess.run(
                    ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
                    check=True, capture_output=True, text=True,
                )
            logger.info("Blocked outbound traffic to %s via %s", ip, self.policy.firewall_backend)
            return True
        except FileNotFoundError:
            logger.error(
                "%s binary not found on host; network isolation skipped for %s",
                self.policy.firewall_backend, ip,
            )
            return False
        except subprocess.CalledProcessError as exc:
            logger.error("Firewall rule injection failed for %s: %s", ip, exc.stderr)
            return False

    # ---------- Orchestration ----------
    def respond(self, alert: Alert) -> ContainmentResult:
        result = ContainmentResult(alert_id=alert.alert_id, pid=alert.pid)

        if not self.policy.enabled:
            result.actions_taken.append("containment_disabled_alert_only")
            return result

        if not alert.requires_containment or alert.pid is None:
            result.actions_taken.append("no_pid_target_alert_only")
            return result

        pid = alert.pid

        # 1. Freeze
        if self._freeze(pid):
            result.actions_taken.append(f"SIGSTOP:{pid}")
        else:
            result.actions_taken.append(f"SIGSTOP_FAILED:{pid}")

        # 2. Forensics (must happen before kill, while /proc entries live)
        try:
            artifact = forensics.capture(
                pid, reason=alert.title, technique_ids=[alert.mitre_technique_id]
            )
            path = forensics.persist(artifact, self.policy.forensics_output_dir)
            result.forensic_artifact_path = path
            result.actions_taken.append("FORENSIC_SNAPSHOT_CAPTURED")
        except Exception as exc:  # noqa: BLE001
            logger.exception("Forensic capture failed for pid=%s", pid)
            result.actions_taken.append(f"FORENSIC_CAPTURE_FAILED:{exc}")

        # 3. Kill
        if self.policy.auto_kill:
            killed = self._kill_process_tree(pid)
            if killed:
                result.actions_taken.append(f"SIGKILL:{killed}")
            else:
                result.actions_taken.append(f"SIGKILL_NOOP:{pid}")

        # 4. Network isolation
        if self.policy.auto_network_isolate and alert.raddr:
            ip = alert.raddr[0]
            if self._block_ip(ip):
                result.blocked_ip = ip
                result.actions_taken.append(f"NETWORK_BLOCK:{ip}")
            else:
                result.actions_taken.append(f"NETWORK_BLOCK_FAILED:{ip}")

        logger.warning(
            "Containment executed for alert=%s pid=%s actions=%s",
            alert.alert_id, pid, result.actions_taken,
        )
        return result

    def manual_quarantine(self, pid: int) -> ContainmentResult:
        """Triggered by the dashboard's One-Click Manual Quarantine button."""
        fake_alert = Alert(
            alert_id=f"MANUAL-{int(time.time())}",
            rule_id="MANUAL_QUARANTINE",
            severity="CRITICAL",  # type: ignore[arg-type]
            title="Manual quarantine requested by SecOps analyst",
            description=f"Analyst-initiated quarantine of pid={pid}",
            mitre_tactic="N/A",
            mitre_technique_id="N/A",
            mitre_technique_name="Manual Response",
            pid=pid,
            ppid=None,
            process_name=None,
            cmdline=None,
            raddr=None,
        )
        return self.respond(fake_alert)
