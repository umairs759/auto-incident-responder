"""
agent/config.py
Configuration schema, policy loader, and default rulesets for the
Micro-EDR Endpoint Agent.

All tunables (thresholds, canary paths, server URL, scan intervals) are
externalized to config/edr_policy.json so the agent binary never needs
to be rebuilt to change detection sensitivity.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger("edr.config")

DEFAULT_POLICY_PATH = os.environ.get(
    "EDR_POLICY_PATH", "/etc/micro-edr/edr_policy.json"
)

# Fallback path used in dev / non-installed environments
_LOCAL_POLICY_FALLBACK = str(
    Path(__file__).resolve().parent.parent / "config" / "edr_policy.json"
)


@dataclass
class DetectionPolicy:
    """Detection thresholds and rule parameters."""

    # Reverse shell detection: parent binaries considered "non-interactive"
    # that should never legitimately spawn an interactive shell child.
    suspicious_parent_binaries: List[str] = field(
        default_factory=lambda: [
            "nginx", "apache2", "httpd", "php-fpm", "java", "python3",
            "gunicorn", "uwsgi", "node", "mysqld", "postgres", "redis-server",
            "cron", "crond", "sshd",
        ]
    )
    shell_binaries: List[str] = field(
        default_factory=lambda: ["sh", "bash", "dash", "zsh", "ash", "ksh"]
    )
    # Sockets are flagged if a shell process holds an established outbound
    # connection to a non-loopback IP on any of these "reverse shell" ports
    # OR any ephemeral high port with an interactive tty attached.
    reverse_shell_ports: List[int] = field(
        default_factory=lambda: [4444, 1337, 8443, 9001, 6666, 31337]
    )

    # File Integrity Monitoring / ransomware canary
    canary_paths: List[str] = field(
        default_factory=lambda: [
            "/etc/passwd",
            "/etc/shadow",
            "/opt/edr_canary",
        ]
    )
    # If >= this many canary files are modified within canary_window_secs,
    # fire a CRITICAL ransomware alert.
    canary_modification_threshold: int = 3
    canary_window_secs: int = 10

    # Network scan detection: distinct destination ports contacted by a
    # single PID within scan_window_secs triggers T1046.
    port_scan_distinct_port_threshold: int = 15
    scan_window_secs: int = 5

    # Collector cadence
    process_poll_interval_secs: float = 1.0
    network_poll_interval_secs: float = 1.0
    canary_hash_interval_secs: float = 2.0


@dataclass
class ContainmentPolicy:
    """Active response / containment behavior."""

    enabled: bool = True
    auto_kill: bool = True
    auto_network_isolate: bool = True
    # Grace period between SIGSTOP (freeze for forensics) and SIGKILL
    forensics_capture_timeout_secs: float = 2.0
    firewall_backend: str = "nftables"  # "nftables" or "iptables"
    forensics_output_dir: str = "/var/log/micro-edr/forensics"


@dataclass
class ShipperPolicy:
    """Telemetry shipping / backend connectivity."""

    server_ws_url: str = "ws://localhost:8000/ws/agent"
    server_http_url: str = "http://localhost:8000"
    reconnect_backoff_min_secs: float = 1.0
    reconnect_backoff_max_secs: float = 30.0
    heartbeat_interval_secs: float = 15.0
    ring_buffer_max_events: int = 5000
    enrollment_token: str = os.environ.get("EDR_ENROLLMENT_TOKEN", "")


@dataclass
class AgentPolicy:
    endpoint_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str = field(default_factory=lambda: os.uname().nodename)
    detection: DetectionPolicy = field(default_factory=DetectionPolicy)
    containment: ContainmentPolicy = field(default_factory=ContainmentPolicy)
    shipper: ShipperPolicy = field(default_factory=ShipperPolicy)
    log_level: str = "INFO"

    @classmethod
    def load(cls, path: str | None = None) -> "AgentPolicy":
        candidate = path or DEFAULT_POLICY_PATH
        if not os.path.exists(candidate):
            candidate = _LOCAL_POLICY_FALLBACK

        if not os.path.exists(candidate):
            logger.warning(
                "No policy file found at %s or fallback %s; using built-in defaults",
                path or DEFAULT_POLICY_PATH,
                _LOCAL_POLICY_FALLBACK,
            )
            return cls()

        with open(candidate, "r", encoding="utf-8") as fh:
            raw: Dict[str, Any] = json.load(fh)

        policy = cls()
        if "endpoint_id" in raw:
            policy.endpoint_id = raw["endpoint_id"]
        if "hostname" in raw:
            policy.hostname = raw["hostname"]
        if "log_level" in raw:
            policy.log_level = raw["log_level"]

        for section_name, dataclass_type, attr in (
            ("detection", DetectionPolicy, "detection"),
            ("containment", ContainmentPolicy, "containment"),
            ("shipper", ShipperPolicy, "shipper"),
        ):
            section = raw.get(section_name, {})
            current = getattr(policy, attr)
            for key, value in section.items():
                if hasattr(current, key):
                    setattr(current, key, value)
                else:
                    logger.warning("Unknown %s policy key: %s", section_name, key)

        logger.info("Loaded EDR policy from %s", candidate)
        return policy


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
