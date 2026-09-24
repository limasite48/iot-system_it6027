#!/usr/bin/env python3
"""
IoT Insecure Device Detection & Management Platform - CLI & Server Runner (net-sec)
Course: IT6027 - Cybersecurity Policy and Governance
"""

import sys
import os
import argparse
import asyncio

# Ensure app package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "app"))
sys.path.insert(0, os.path.dirname(__file__))

from app.scanner_engine import SecurityScannerEngine
from app.web.api import app, SCANNER

def print_banner():
    print("""
========================================================================
   IoT INSECURE DEVICE DETECTION & GOVERNANCE PLATFORM (net-sec)
              IT6027 - Cybersecurity Policy and Governance
========================================================================
  [+] Capabilities:
      - IoT Device Fingerprinting (Cameras, Plugs, Gateways via mDNS/UPnP)
      - Firmware & Known CVE Correlation (CVSS v3.1 Scoring)
      - Default Password Auditing against Predefined Dictionary
      - VLAN Scoping, Real-Time Alerts & Interactive Web Dashboard
========================================================================
    """)

async def run_cli_scan(target_cidr: str = None):
    print_banner()
    engine = SecurityScannerEngine()
    print(f"[*] Commencing security audit scan (Target: {target_cidr or 'Local Hotspot Subnet'})...")
    devices = await engine.execute_network_scan(target_cidr=target_cidr)
    stats = engine.get_summary_statistics()

    print("\n" + "=" * 70)
    print(f"{'DEVICE INVENTORY & VULNERABILITY SUMMARY':^70}")
    print("=" * 70)
    print(f"  Total Nodes Discovered:        {stats['total_devices']}")
    print(f"  Insecure / Vulnerable Devices: {stats['vulnerable_devices']}")
    print(f"  Default Passwords Found:       {stats['default_passwords_found']}")
    print(f"  Quarantine Isolation Actions:  {stats['quarantine_recommended']}")
    print("-" * 70)

    for d in devices:
        if d.get("is_open_access"):
            auth_flag = "[!] OPEN ACCESS (NO PASSWORD)"
        elif d.get("default_credentials_found"):
            auth_flag = "[!] DEFAULT CREDS ACCEPTED"
        else:
            auth_flag = "[+] Protected"

        print(f"\n[*] Device: {d['ip']:<15} | Type: {d['device_type']:<15} | Vendor: {d['vendor']}")
        print(f"    MAC:    {d['mac']:<17} | Ports: {d['open_ports']}")
        print(f"    VLAN:   {d['vlan']['name']}")
        print(f"    Status: Risk={d['risk_level']} | Auth={auth_flag}")

        if d.get("credential_findings"):
            for f in d["credential_findings"]:
                tag = "OPEN ACCESS" if f.get("is_open_access") else "DEFAULT LOGIN"
                print(f"    >> [CRITICAL VIOLATION] Port {f['port']} {tag}: {f['credential']}")

        if d.get("cves"):
            print("    >> Matched Known CVEs:")
            for cve in d["cves"]:
                print(f"       * {cve['cve_id']} (CVSS {cve['cvss_score']} {cve['severity']}): {cve['title']}")

        if d.get("scoping_policy", {}).get("quarantine_required"):
            print(f"    >> [VLAN ACTION] {d['scoping_policy']['policy_message']}")
            print(f"       Recommended Scope: {d['scoping_policy']['recommended_vlan']}")

    print("\n" + "=" * 70)
    print("[+] Audit scan completed.")

def run_web_server(host="0.0.0.0", port=8000):
    print_banner()
    print(f"[*] Starting Web Dashboard on http://localhost:{port}")
    print(f"    Access from any browser on this machine or the IoT edge subnet.\n")
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")

def main():
    parser = argparse.ArgumentParser(description="IoT Insecure Device Detection & Management Platform")
    parser.add_argument("--scan", action="store_true", help="Run a one-time CLI scan and print results to terminal")
    parser.add_argument("--target", type=str, default=None, help="Target CIDR network (defaults to dynamically detected edge/hotspot subnet)")
    parser.add_argument("--web", action="store_true", help="Start the FastAPI web dashboard")
    parser.add_argument("--port", type=int, default=8000, help="Port for the web server (default 8000)")

    args = parser.parse_args()

    if args.scan:
        asyncio.run(run_cli_scan(args.target))
    else:
        # Default behavior: run web server (with CLI scan available via web UI)
        run_web_server(port=args.port)

if __name__ == "__main__":
    main()
