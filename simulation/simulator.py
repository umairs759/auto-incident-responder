#!/usr/bin/env python3
"""
Autonomous Micro-EDR Safe Red-Team Attack Simulator.
Triggers realistic adversary techniques mapped explicitly to MITRE ATT&CK:
- T1059.004: Interactive shell spawning from non-interactive parent (Reverse Shell)
- T1486: Ransomware canary corruption / rapid payload overwrite
- T1046: Network service discovery port scan
Validates autonomous containment latencies and alert reporting.
"""

import argparse
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

CANARY_DIR = Path("/tmp/.edr_canaries")


def print_banner() -> None:
    print(r"""
  __  __ _                  ______ _____  _____     _____ _                 _       _             
 |  \/  (_)                |  ____|  __ \|  __ \   / ____(_)               | |     | |            
 | \  / |_  ___ _ __ ___   | |__  | |  | | |__) | | (___  _ _ __ ___  _   _| | __ _| |_ ___  _ __ 
 | |\/| | |/ __| '__/ _ \  |  __| | |  | |  _  /   \___ \| | '_ ` _ \| | | | |/ _` | __/ _ \| '__|
 | |  | | | (__| | | (_) | | |____| |__| | | \ \   ____) | | | | | | | |_| | | (_| | || (_) | |   
 |_|  |_|_|\___|_|  \___/  |______|_____/|_|  \_\ |_____/|_|_| |_| |_|\__,_|_|\__,_|\__\___/|_|   
    """)
    print("[*] ADVERSARY SIMULATION & ACTIVE DEFENSE VERIFICATION HARNESS")
    print("[*] Target Environment: Linux Kernel Runtime Telemetry\n")


def simulate_reverse_shell() -> None:
    """
    Simulates MITRE ATT&CK T1059.004 (Unix Shell).
    Forks an interactive /bin/bash shell from a non-interactive Python process.
    """
    print("[+] [SCENARIO 1: REVERSE SHELL EXECUTION] (MITRE T1059.004)")
    print("[*] Spawning non-interactive parent attempting to execute interactive shell...")

    attack_payload = (
        "import subprocess, time; "
        "time.sleep(0.5); "
        "subprocess.run(['/bin/bash', '-c', 'sleep 10'])"
    )

    start_time = time.time()
    proc = subprocess.Popen(
        [sys.executable, "-c", attack_payload],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    print(f"[*] Target malicious process spawned with PID: {proc.pid}")
    print("[*] Monitoring autonomous containment latency...")

    killed = False
    for _ in range(15):
        time.sleep(0.2)
        status = proc.poll()
        if status is not None:
            latency = (time.time() - start_time) * 1000
            print(f"[✓] VERIFICATION SUCCESS: Target PID {proc.pid} terminated by Active Defense!")
            print(f"[✓] Containment SLA: {latency:.2f}ms | Exit Signal: {status}\n")
            killed = True
            break

    if not killed:
        print(f"[!] Warning: Target PID {proc.pid} was not killed in the sampling window.")
        print("[!] Verify that the Micro-EDR agent daemon is actively running with root privileges.\n")
        proc.kill()


def simulate_canary_ransomware() -> None:
    """
    Simulates MITRE ATT&CK T1486 (Data Encrypted for Impact).
    Simulates ransomware overwriting decoy files inside /tmp/.edr_canaries/.
    """
    print("[+] [SCENARIO 2: RANSOMWARE ENCRYPTION CANARY] (MITRE T1486)")
    CANARY_DIR.mkdir(parents=True, exist_ok=True)
    target_canary = CANARY_DIR / "customer_database_export.sql"

    if not target_canary.exists():
        with open(target_canary, "w", encoding="utf-8") as f:
            f.write("SAMPLE CANARY DATABASE PAYLOAD -- CLASSIFICATION RESTRICTED\n")

    print(f"[*] Simulating malicious encryption on canary trap: {target_canary}")
    pseudo_encrypted_data = os.urandom(512)

    with open(target_canary, "wb") as f:
        f.write(pseudo_encrypted_data)

    print("[✓] Canary file modified. SHA-256 digest corrupted.")
    print("[✓] Decoy tripwire fired. Verify CRITICAL alert triage on SecOps console.\n")


def simulate_reconnaissance_scan() -> None:
    """
    Simulates MITRE ATT&CK T1046 (Network Service Discovery).
    Executes a high-velocity TCP connect scan across common internal ports.
    """
    print("[+] [SCENARIO 3: NETWORK RECONNAISSANCE SCAN] (MITRE T1046)")
    target_ports = [21, 22, 80, 443, 3306, 5432, 6379, 8000, 8080]
    print(f"[*] Executing TCP port scan sweep on localhost: {target_ports}")

    def probe(port: int):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

    threads = []
    for p in target_ports:
        t = threading.Thread(target=probe, args=(p,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("[✓] Port scan sweep concluded.\n")


def run_full_suite() -> None:
    print_banner()
    simulate_reverse_shell()
    time.sleep(1)
    simulate_canary_ransomware()
    time.sleep(1)
    simulate_reconnaissance_scan()
    print("[+] All attack scenarios executed successfully.")
    print("[+] Inspect real-time triage at http://127.0.0.1:8000/dashboard/\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Autonomous Micro-EDR Safe Adversary Simulator")
    parser.add_argument(
        "--scenario",
        choices=["shell", "ransomware", "recon", "all"],
        default="all",
        help="Select attack simulation scenario (default: all)"
    )
    args = parser.parse_args()

    if args.scenario == "shell":
        print_banner()
        simulate_reverse_shell()
    elif args.scenario == "ransomware":
        print_banner()
        simulate_canary_ransomware()
    elif args.scenario == "recon":
        print_banner()
        simulate_reconnaissance_scan()
    else:
        run_full_suite()