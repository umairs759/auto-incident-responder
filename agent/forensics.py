"""
agent/forensics.py
Captures a structured forensic artifact for a malicious PID BEFORE it is
terminated: environment variables, open file descriptors, /proc/<pid>/status,
memory maps, and full command line. Written as JSON for chain-of-custody.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

import psutil

logger = logging.getLogger("edr.forensics")


def _read_proc_file(pid: int, filename: str) -> Optional[str]:
    path = f"/proc/{pid}/{filename}"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None


def _read_open_fds(pid: int) -> Dict[str, str]:
    fds: Dict[str, str] = {}
    fd_dir = f"/proc/{pid}/fd"
    try:
        for fd in os.listdir(fd_dir):
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
                fds[fd] = target
            except (FileNotFoundError, PermissionError, OSError):
                continue
    except (FileNotFoundError, PermissionError):
        pass
    return fds


def _read_environ(pid: int) -> Dict[str, str]:
    raw = _read_proc_file(pid, "environ")
    if not raw:
        return {}
    env: Dict[str, str] = {}
    for entry in raw.split("\x00"):
        if "=" in entry:
            k, _, v = entry.partition("=")
            env[k] = v
    return env


def _parse_status(pid: int) -> Dict[str, str]:
    raw = _read_proc_file(pid, "status")
    if not raw:
        return {}
    status: Dict[str, str] = {}
    for line in raw.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            status[k.strip()] = v.strip()
    return status


def capture(pid: int, reason: str, technique_ids: list[str]) -> Dict[str, Any]:
    """
    Captures a complete forensic snapshot of `pid`. Must be called BEFORE
    the process is signalled, since /proc entries vanish on exit.
    """
    artifact: Dict[str, Any] = {
        "pid": pid,
        "captured_at": time.time(),
        "reason": reason,
        "mitre_technique_ids": technique_ids,
        "status": _parse_status(pid),
        "environ": _read_environ(pid),
        "open_fds": _read_open_fds(pid),
        "cmdline": None,
        "cwd": None,
        "exe": None,
        "maps": _read_proc_file(pid, "maps"),
    }

    try:
        proc = psutil.Process(pid)
        artifact["cmdline"] = proc.cmdline()
        artifact["cwd"] = proc.cwd()
        artifact["exe"] = proc.exe()
        artifact["username"] = proc.username()
        artifact["create_time"] = proc.create_time()
        artifact["connections"] = [
            {
                "laddr": tuple(c.laddr) if c.laddr else None,
                "raddr": tuple(c.raddr) if c.raddr else None,
                "status": c.status,
            }
            for c in proc.net_connections(kind="inet")
        ]
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as exc:  # noqa: BLE001
        artifact["capture_error"] = str(exc)

    return artifact


def persist(artifact: Dict[str, Any], output_dir: str) -> str:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"forensic_{artifact['pid']}_{int(artifact['captured_at'])}.json"
    full_path = os.path.join(output_dir, filename)
    with open(full_path, "w", encoding="utf-8") as fh:
        json.dump(artifact, fh, indent=2, default=str)
    logger.info("Forensic artifact written: %s", full_path)
    return full_path
