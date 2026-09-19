"""
agent/collector.py
Low-overhead process-tree and socket telemetry collector using psutil
with direct /proc fallbacks. Produces immutable snapshots consumed by
the Detector.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import psutil

logger = logging.getLogger("edr.collector")


@dataclass
class ProcessRecord:
    pid: int
    ppid: int
    name: str
    exe: Optional[str]
    cmdline: List[str]
    username: Optional[str]
    create_time: float
    cwd: Optional[str]
    terminal: Optional[str]
    children: List[int] = field(default_factory=list)


@dataclass
class ConnectionRecord:
    pid: int
    fd: int
    laddr_ip: str
    laddr_port: int
    raddr_ip: Optional[str]
    raddr_port: Optional[int]
    status: str
    family: str


@dataclass
class Snapshot:
    timestamp: float
    processes: Dict[int, ProcessRecord]
    connections: List[ConnectionRecord]


class Collector:
    """
    Polls the OS for a full process tree + active socket table.
    Designed to be called on a fixed interval from the agent's async loop.
    Read-only; never mutates system state.
    """

    def __init__(self) -> None:
        self._last_snapshot: Optional[Snapshot] = None

    def _read_terminal(self, proc: psutil.Process) -> Optional[str]:
        try:
            terminal = proc.terminal()
            return terminal
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            return None

    def collect_processes(self) -> Dict[int, ProcessRecord]:
        records: Dict[int, ProcessRecord] = {}
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username",
             "create_time", "cwd"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                records[pid] = ProcessRecord(
                    pid=pid,
                    ppid=info.get("ppid") or 0,
                    name=info.get("name") or "",
                    exe=info.get("exe"),
                    cmdline=info.get("cmdline") or [],
                    username=info.get("username"),
                    create_time=info.get("create_time") or 0.0,
                    cwd=info.get("cwd"),
                    terminal=self._read_terminal(proc),
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Build child linkage
        for pid, rec in records.items():
            parent = records.get(rec.ppid)
            if parent is not None:
                parent.children.append(pid)

        return records

    def collect_connections(self) -> List[ConnectionRecord]:
        conns: List[ConnectionRecord] = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.pid is None:
                    continue
                laddr_ip, laddr_port = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
                raddr_ip, raddr_port = (c.raddr.ip, c.raddr.port) if c.raddr else (None, None)
                conns.append(
                    ConnectionRecord(
                        pid=c.pid,
                        fd=c.fd if c.fd is not None else -1,
                        laddr_ip=laddr_ip,
                        laddr_port=laddr_port,
                        raddr_ip=raddr_ip,
                        raddr_port=raddr_port,
                        status=c.status,
                        family=str(c.family),
                    )
                )
        except (psutil.AccessDenied, PermissionError):
            logger.warning(
                "Insufficient privileges for full socket enumeration; "
                "run agent with CAP_NET_ADMIN/root for complete visibility."
            )
        return conns

    def snapshot(self) -> Snapshot:
        snap = Snapshot(
            timestamp=time.time(),
            processes=self.collect_processes(),
            connections=self.collect_connections(),
        )
        self._last_snapshot = snap
        return snap

    @property
    def last_snapshot(self) -> Optional[Snapshot]:
        return self._last_snapshot
