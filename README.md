# Autonomous Micro-EDR & Active Incident Response Engine
> High-performance Linux endpoint detection, volatile memory forensics, and autonomous containment.

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-orange.svg)](https://attack.mitre.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20Kernel%20%2F%20proc-lightgrey.svg)](https://kernel.org)

An enterprise-grade, lightweight Endpoint Detection & Response (EDR) daemon paired with an active defense containment engine and real-time SecOps telemetry dashboard. Built specifically to mitigate Linux threat vectors with zero human latency (< 15ms).

---

## Key Highlights

- **Low-Overhead Telemetry Sampling**: Inspects `/proc` hierarchies and socket states using an optimized non-blocking loop (< 1.5% CPU overhead).
- **Anomalous Shell Hunter**: Discovers interactive shells (`/bin/bash`, `/bin/sh`) spawned out of non-interactive services (e.g., Nginx, Gunicorn, Python, Node.js).
- **Active Containment Engine**:
  1. **Atomic Process Freeze**: Transmits `SIGSTOP` across the entire process group to halt fork bombs and memory mutation.
  2. **Volatile Forensic Snapshot**: Dumps `/proc/<pid>/status`, open file descriptors, active sockets, and environment variables into structured JSON artifacts.
  3. **Unconditional Neutralization**: Delivers `SIGKILL` down the process tree hierarchy.
  4. **Dynamic C2 Severance**: Injects atomic `iptables` drop rules to drop inbound and outbound traffic with the malicious IP.
- **Ransomware Canary Traps**: Cryptographic SHA-256 tripwire monitoring on decoy files (`/tmp/.edr_canaries`) to detect unauthorized modifications.
- **Bi-directional WebSocket Pipeline**: Real-time event streaming and operator-initiated manual containment routing.

---

## MITRE ATT&CK® Correlation Matrix

| Tactic | Technique ID | Technique Name | Detection Heuristic | Autonomous Containment Action |
| :--- | :--- | :--- | :--- | :--- |
| **Execution** | `T1059.004` | Unix Shell | Non-interactive server parent spawns interactive shell | `SIGSTOP` -> Forensic Snapshot -> `SIGKILL` Process Tree |
| **Privilege Escalation** | `T1548.001` | Setuid and Setgid | Detection of elevated execution flags on non-root binaries | Target Process Termination (`SIGKILL`) |
| **Discovery** | `T1046` | Network Service Discovery | Rapid socket sweep across multiple local loopback ports | Rate-limit & Flag Suspicious PID |
| **Command & Control** | `T1071.001` | Web Protocols | Shell process holding established outbound connection | Dynamic `iptables -I OUTPUT -d <IP> -j DROP` |
| **Impact** | `T1486` | Data Encrypted for Impact | Rapid SHA-256 hash mutation or canary file tampering | Offending PID Termination & Isolation Alert |

---

## Architecture Flow

```text
[ Linux Host Space ]
       │
       ├─► /proc Telemetry (Process Tree, Open FDs, Sockets)
       ├─► Canary Trap Files (SHA-256 File Integrity Watchdog)
       ▼
[ Micro-EDR Agent ] ────(Heuristic Match)────► [ Active Containment ]
       │                                            │  ├─ SIGSTOP (Freeze)
       │                                            │  ├─ Dump Forensics
       │                                            │  ├─ SIGKILL (Kill Tree)
       │                                            │  └─ iptables IP Drop
       ▼ (Asynchronous WebSocket Client)
[ Central Telemetry Server (FastAPI) ]
       │
       ├─► Relational Store (SQLite / PostgreSQL)
       └─► WebSocket Broadcast Hub
             ▼
[ Interactive SecOps Dashboard ]
       ├─ Real-Time Alert Triage Feed
       ├─ Dynamic MITRE ATT&CK Matrix Widget
       └─ Volatile Memory Forensic JSON Modal
```
## Quickstart & Execution
1. Bare-Metal Linux Setup (Local Kali / Ubuntu)
```
# Clone and enter project directory
cd /home/kali/Desktop/auto-incident-responder

# Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Terminal 1: Launch Central Telemetry Server
uvicorn server.app:app --host 0.0.0.0 --port 8000

# Terminal 2: Launch Micro-EDR Agent (Root required for SIGKILL & iptables)
sudo ./venv/bin/python -m agent.agent
```
Open your browser at http://127.0.0.1:8000/dashboard/ to view the SecOps Command Center.

## 2. Live Adversary Attack Simulation

In a separate terminal, trigger safe test scenarios to validate detection and autonomous neutralization:
``` # Execute full attack simulation suite
python3 simulation/simulator.py --scenario all

# Or run individual attack scenarios
python3 simulation/simulator.py --scenario shell
python3 simulation/simulator.py --scenario ransomware
python3 simulation/simulator.py --scenario recon
```
## Deployment Options
Docker Compose

Run the entire decoupled architecture with a single command:
```docker compose -f deploy/docker-compose.yml up --build
```
### Systemd Production Daemon

To run the agent continuously in the background on bare-metal systems:
```sudo cp deploy/micro-edr-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now micro-edr-agent
sudo journalctl -u micro-edr-agent -f
``` 
## Interview & Engineering Talking Points

    Why /proc polling vs eBPF?

    While eBPF offers kernel-level kprobe attachments, an optimized /proc reader provides universal compatibility across legacy Linux kernels without requiring kernel-header recompilation or BTF (BPF Type Format) dependencies, maintaining a negligible CPU footprint when bounded by targeted attribute projections.

    Race Condition Handling in Containment:

    To prevent malicious processes from spawning fork bombs before termination, the agent uses an atomic two-step mitigation: delivering SIGSTOP first to suspend execution threads across the process tree, taking a forensic snapshot, and finally executing SIGKILL.

    Volatile Artifact Retention:

    Crucial incident evidence (such as dynamically loaded command-line arguments and deleted socket file descriptors) vanishes upon process exit. The agent extracts these parameters while the process is suspended, persisting forensic JSON artifacts to disk prior to termination.```