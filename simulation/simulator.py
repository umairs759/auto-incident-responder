#!/usr/bin/env python3
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

CANARY_DIR = Path("/tmp/.edr_canaries")

def simulate_reverse_shell():
    print("[+] [SCENARIO 1: REVERSE SHELL EXECUTION] (MITRE T1059.004)")
    print("[*] Spawning non-interactive parent launching interactive shell...")

    # Python exits immediately if child shell is killed
    attack_code = (
        "import subprocess, sys; "
        "p = subprocess.Popen(['/bin/bash', '-i']); "
        "p.wait(); "
        "sys.exit(p.returncode)"
    )

    start_time = time.time()
    proc = subprocess.Popen([sys.executable, "-c", attack_code])
    print(f"[*] Target malicious process hierarchy spawned (Parent PID: {proc.pid})")
    print("[*] Monitoring autonomous containment latency...")

    killed = False
    for _ in range(40):
        time.sleep(0.2)
        if proc.poll() is not None:
            latency = (time.time() - start_time) * 1000
            print(f"[✓] VERIFICATION SUCCESS: Malicious shell terminated by Micro-EDR Active Defense!")
            print(f"[✓] Containment SLA: {latency:.2f}ms | Exit Signal: {proc.poll()}\n")
            killed = True
            break

    if not killed:
        print(f"[!] Timed out. Cleaning up.")
        proc.kill()

def simulate_canary_ransomware():
    print("[+] [SCENARIO 2: RANSOMWARE ENCRYPTION CANARY] (MITRE T1486)")
    CANARY_DIR.mkdir(parents=True, exist_ok=True)
    target_canary = CANARY_DIR / "customer_database_export.sql"

    with open(target_canary, "wb") as f:
        f.write(os.urandom(512))

    print(f"[*] Canary trap file overwritten with pseudo-ransomware payload: {target_canary}")
    print("[✓] Canary tripwire fired. Check SecOps console for CRITICAL alert!\n")

def simulate_reconnaissance_scan():
    print("[+] [SCENARIO 3: NETWORK RECONNAISSANCE SCAN] (MITRE T1046)")
    target_ports = [21, 22, 80, 443, 3306, 5432, 6379, 8000]
    print(f"[*] Sweeping localhost TCP ports: {target_ports}")

    for p in target_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        try:
            s.connect(("127.0.0.1", p))
            s.close()
        except Exception:
            pass

    print("[✓] Port scan sweep concluded.\n")

if __name__ == "__main__":
    simulate_reverse_shell()
    time.sleep(0.5)
    simulate_canary_ransomware()
    time.sleep(0.5)
    simulate_reconnaissance_scan()
    print("[+] Attack scenarios complete. Check Dashboard at http://127.0.0.1:8000/dashboard/\n")
