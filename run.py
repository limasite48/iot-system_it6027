#!/usr/bin/env python3
"""
All-in-One IoT Insecure Device Detection & Governance Platform Runner
Course: IT6027 - Cybersecurity Policy and Governance

Unified entrypoint that orchestrates the local testbed mock IoT devices
and launches the network security auditor and SOC dashboard.
"""

import sys
import os
import atexit
import signal
import argparse
import asyncio
import time

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
NET_SEC_DIR = os.path.join(ROOT_DIR, "net-sec")
MOCK_OBJ_DIR = os.path.join(ROOT_DIR, "mock-object")

if NET_SEC_DIR not in sys.path:
    sys.path.insert(0, NET_SEC_DIR)
if MOCK_OBJ_DIR not in sys.path:
    sys.path.insert(0, MOCK_OBJ_DIR)

from fleet_manager import start_fleet, stop_fleet
from run_scanner import run_web_server, run_cli_scan

_fleet_started = False

def cleanup():
    global _fleet_started
    if _fleet_started:
        print("\n[*] Shutting down mock IoT device fleet...")
        stop_fleet()
        _fleet_started = False

def signal_handler(sig, frame):
    cleanup()
    sys.exit(0)

def main():
    global _fleet_started

    parser = argparse.ArgumentParser(
        description="Unified IoT Security Auditor & Testbed Platform Runner (IT6027)"
    )
    parser.add_argument("--scan", action="store_true", help="Execute one-shot CLI security audit and print report to terminal")
    parser.add_argument("--target", type=str, default="ALL", help="Target scope (default 'ALL' to audit both mock and physical edge devices)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Web dashboard host (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Web dashboard port (default 8000)")
    parser.add_argument(
        "--device", "--devices", "--camera", "--cameras",
        dest="devices",
        type=int,
        default=4,
        help="Number of virtual mock IoT device nodes to start (default 4)"
    )
    parser.add_argument("--no-fleet", action="store_true", help="Disable virtual mock fleet (pure physical hardware / external mode)")

    args = parser.parse_args()

    # Register exit handlers for graceful teardown
    atexit.register(cleanup)
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    print("""
========================================================================
   IoT INSECURE DEVICE DETECTION & GOVERNANCE PLATFORM (ALL-IN-ONE)
              IT6027 - Cybersecurity Policy and Governance
========================================================================
  [+] Unified Architecture:
      - Device-Agnostic SOC Dashboard & Audit Engine
      - Multi-Subnet Sweeper (Physical Edge Hotspot + Virtual Mock Fleet)
      - Non-intrusive Black-Box Fingerprinting & Firmware CVE Correlation
      - Default Credential / Open Access Auditing & SSVC Prioritization
========================================================================
    """)

    if not args.no_fleet:
        print(f"[*] Initializing virtual mock IoT testbed ({args.devices} nodes on 127.0.0.2+)...")
        start_fleet(count=args.devices, use_loopback_ips=True)
        _fleet_started = True
        time.sleep(0.8)
    else:
        print("[i] Mock fleet disabled (--no-fleet). Operating strictly on physical/existing network targets.")

    if args.scan:
        print(f"[*] Running one-shot network security audit on target: '{args.target}'...")
        asyncio.run(run_cli_scan(args.target))
        cleanup()
    else:
        print(f"[*] Starting unified SOC dashboard on http://localhost:{args.port}")
        print("    Press Ctrl+C to terminate the platform and all simulated endpoints.\n")
        try:
            run_web_server(host=args.host, port=args.port)
        finally:
            cleanup()

if __name__ == "__main__":
    main()
