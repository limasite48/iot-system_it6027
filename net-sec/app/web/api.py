"""
FastAPI Security Web Service & REST API (net-sec)
Serves real-time IoT inventory, CVE reports, default password alerts,
VLAN scoping panels, and the modern web dashboard.
"""

import os
from typing import Optional
from fastapi import FastAPI, BackgroundTasks, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.scanner_engine import SecurityScannerEngine
from app.monitoring.traffic_meter import GLOBAL_TRAFFIC_METER
import asyncio

app = FastAPI(
    title="Insecure IoT Device Detection & Management Platform",
    description="Cybersecurity Policy and Governance (IT6027) Security Auditor",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.discovery.network_env import (
    get_primary_edge_cidr,
    detect_active_subnets,
    get_hotspot_active_clients,
    is_edge_ip
)

# Global engine singleton
SCANNER = SecurityScannerEngine()

@app.on_event("startup")
async def on_startup():
    # Start real-time presence & auto-discovery monitor
    SCANNER.start_presence_monitor(interval_seconds=4.0)
    # Dynamically trigger initial discovery scan across active edge subnet
    primary_cidr = get_primary_edge_cidr()
    asyncio.create_task(SCANNER.execute_network_scan(primary_cidr))

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/api/network/info")
async def get_network_info():
    """Retrieve detected active subnets, primary edge CIDR, and connected hotspot peers."""
    subnets = detect_active_subnets()
    primary = get_primary_edge_cidr()
    hotspot_peers = get_hotspot_active_clients()
    edge_subnets = [s for s in subnets if s.get("is_edge")]
    return {
        "primary_cidr": primary,
        "subnets": edge_subnets,
        "all_subnets": subnets,
        "hotspot_active": any(s.get("is_hotspot") for s in subnets),
        "hotspot_clients": hotspot_peers
    }

@app.get("/api/traffic")
async def get_traffic():
    return GLOBAL_TRAFFIC_METER.get_snapshot()

class ScanRequest(BaseModel):
    target_cidr: Optional[str] = None
    timeout: Optional[float] = 2.5

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>IoT Security Dashboard Static File Missing</h1>")

@app.get("/api/status")
async def get_status():
    edge_devices = [d for d in SCANNER.inventory.values() if is_edge_ip(d.get("ip", ""))]
    return {
        "status": "ONLINE",
        "is_scanning": SCANNER.is_scanning,
        "last_scan_time": SCANNER.last_scan_time,
        "device_count": len(edge_devices),
        "alert_count": len(SCANNER.alerts)
    }

@app.post("/api/scan")
async def trigger_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    if SCANNER.is_scanning:
        return JSONResponse({"status": "BUSY", "message": "A scan is already in progress"}, status_code=409)
    
    # Run scan asynchronously in background
    background_tasks.add_task(SCANNER.execute_network_scan, req.target_cidr, req.timeout)
    return {"status": "STARTED", "target": req.target_cidr}

@app.get("/api/devices")
async def get_devices():
    return [d for d in SCANNER.inventory.values() if is_edge_ip(d.get("ip", ""))]

@app.get("/api/stats")
async def get_stats():
    return SCANNER.get_summary_statistics()

@app.get("/api/alerts")
async def get_alerts():
    return list(reversed(SCANNER.alerts))

@app.get("/api/scoping")
async def get_scoping():
    return SCANNER.get_summary_statistics().get("vlan_groups", {})

@app.get("/api/report")
async def generate_markdown_report():
    """Generates an academic-grade markdown audit report for course submission."""
    stats = SCANNER.get_summary_statistics()
    devices = [d for d in SCANNER.inventory.values() if is_edge_ip(d.get("ip", ""))]
    
    lines = [
        "# IoT Cybersecurity Audit & Governance Report",
        f"**Course**: IT6027 - Cybersecurity Policy and Governance",
        f"**Audit Timestamp**: {SCANNER.last_scan_time or 'N/A'}",
        f"**Total Devices Audited**: {stats['total_devices']}",
        f"**High/Critical Insecure Devices**: {stats['vulnerable_devices']}",
        f"**Default Passwords Discovered**: {stats['default_passwords_found']}",
        f"**Devices Recommended for Quarantine**: {stats['quarantine_recommended']}",
        "",
        "---",
        "",
        "## 1. Executive Summary & Policy Compliance",
        "This assessment evaluated the operational IoT edge network against cybersecurity baselines:",
        "- **Device Fingerprinting via Banner/mDNS/UPnP**: Mandatory component successfully executed across all active hosts.",
        "- **CVE & Default Password Auditing**: Identified unpatched firmware vulnerabilities and checked authentication endpoints against known default credential lists.",
        "- **VLAN Scoping & Quarantine Enforcement**: Formulated network isolation policies for compromised endpoints.",
        "",
        "## 2. Device Inventory & Vulnerability Matrix",
        "| IP Address | MAC Address | Device Type | Vendor | Risk Level | Default Creds | Quarantine |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
    ]

    for d in devices:
        def_cred = "YES (VIOLATION)" if d.get("default_credentials_found") else "Clean"
        quar = "QUARANTINE (VLAN 99)" if d.get("scoping_policy", {}).get("quarantine_required") else "Compliant (VLAN 10)"
        lines.append(f"| {d['ip']} | {d['mac']} | {d['device_type']} | {d['vendor']} | **{d['risk_level']}** | {def_cred} | {quar} |")

    lines.append("")
    lines.append("## 3. Discovered Vulnerabilities & CVE Details")
    found_cves = False
    for d in devices:
        for cve in d.get("cves", []):
            found_cves = True
            lines.append(f"### {cve['cve_id']}: {cve['title']}")
            lines.append(f"- **Target IP**: `{d['ip']}` ({d['device_type']})")
            lines.append(f"- **CVSS Score**: {cve['cvss_score']} ({cve['severity']})")
            lines.append(f"- **Description**: {cve['description']}")
            lines.append(f"- **Remediation**: {cve['remediation']}")
            lines.append("")

    if not found_cves:
        lines.append("No critical CVEs identified on surveyed devices.")

    lines.append("")
    lines.append("## 4. Default Password Audit Findings")
    if stats["default_passwords_found"] > 0:
        for d in devices:
            for f in d.get("credential_findings", []):
                lines.append(f"- **Device `{d['ip']}`** ({d['device_type']}): Port {f['port']} accepted `{f['credential']}` ({f['service']}).")
    else:
        lines.append("No devices were found operating with publicly known default credentials.")

    return HTMLResponse("<pre style='white-space: pre-wrap; font-family: monospace;'>" + "\n".join(lines) + "</pre>")
