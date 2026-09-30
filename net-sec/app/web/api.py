"""
FastAPI Security Web Service & REST API (net-sec)
Serves real-time IoT inventory, CVE reports, default password alerts,
declarative policy checks, auditor triage verification, scope checks,
and the modern web dashboard.
"""

import os
import asyncio
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, BackgroundTasks, Query, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.scanner_engine import SecurityScannerEngine
from app.monitoring.traffic_meter import GLOBAL_TRAFFIC_METER
from app.monitoring.alert_dispatcher import GLOBAL_ALERT_DISPATCHER
from app.audit.triage import GLOBAL_TRIAGE_MANAGER
from app.scoping.scope_service import GLOBAL_SCOPE_MANAGER
from app.audit.policy_engine import GLOBAL_POLICY_ENGINE
from app.audit.cve_manager import GLOBAL_CVE_MANAGER
from app.audit.cve_matcher import match_cves_for_device
from app.audit.contextual_prioritizer import evaluate_device_context
from app.discovery.network_env import (
    get_primary_edge_cidr,
    detect_active_subnets,
    get_hotspot_active_clients,
    is_edge_ip
)

from contextlib import asynccontextmanager

# Global engine singleton
SCANNER = SecurityScannerEngine()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start real-time presence & auto-discovery monitor
    SCANNER.start_presence_monitor(interval_seconds=4.0)
    # Trigger initial discovery scan across all authorized edge subnets (including mock testbed fleet)
    asyncio.create_task(SCANNER.execute_network_scan("ALL"))
    yield

app = FastAPI(
    title="Insecure IoT Device Detection & Management Platform",
    description="Cybersecurity Policy and Governance (IT6027) Security Auditor",
    version="2.0.0",
    lifespan=lifespan
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Request Models
class ScanRequest(BaseModel):
    target_cidr: Optional[str] = None
    timeout: Optional[float] = 2.5

class TriageRequest(BaseModel):
    status: str  # "APPROVED" or "REJECTED"
    auditor_notes: Optional[str] = ""
    reviewer: Optional[str] = "Security Auditor"

class WebhookConfigRequest(BaseModel):
    webhook_url: str
    enabled: bool = True

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>IoT Security Dashboard Static File Missing</h1>")

# Core Network & Status Endpoints
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

@app.get("/api/status")
async def get_status():
    edge_devices = [d for d in SCANNER.inventory.values() if is_edge_ip(d.get("ip", ""))]
    return {
        "status": "ONLINE",
        "is_scanning": SCANNER.is_scanning,
        "last_scan_time": SCANNER.last_scan_time,
        "current_scan_id": SCANNER.current_scan_id,
        "current_stage": SCANNER.current_stage,
        "device_count": len(edge_devices),
        "alert_count": len(SCANNER.alerts)
    }

# Scope Management Endpoints (ref_1.md Module G1)
@app.get("/api/scope/check")
async def check_scope(cidr: Optional[str] = Query(None)):
    """Verifies whether target CIDR is authorized for scanning."""
    target = cidr or "ALL"
    res = GLOBAL_SCOPE_MANAGER.check_scope(target)
    return res

@app.get("/api/scope/allowed")
async def get_allowed_scopes():
    """Lists all configured and permitted edge audit boundaries."""
    return GLOBAL_SCOPE_MANAGER.get_authorized_scopes()

# Scan Execution & History Endpoints (ref_1.md Module G2)
@app.post("/api/scan")
async def trigger_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    if SCANNER.is_scanning:
        return JSONResponse({
            "status": "BUSY",
            "message": f"A scan is already in progress (Stage: {SCANNER.current_stage})"
        }, status_code=409)
    
    # Pre-flight Scope Check
    target = req.target_cidr or "ALL"
    scope_eval = GLOBAL_SCOPE_MANAGER.check_scope(target)
    if not scope_eval.get("allowed"):
        return JSONResponse({
            "status": "REJECTED",
            "message": scope_eval.get("reason", "Target CIDR outside permitted audit boundary.")
        }, status_code=403)

    # Immediately mark scanning and current stage for instant UI reactivity
    SCANNER.is_scanning = True
    SCANNER.current_stage = "STAGE_1_SCOPE_VERIFICATION"
    background_tasks.add_task(SCANNER.execute_network_scan, target, req.timeout)
    return {"status": "STARTED", "target": target}

@app.get("/api/scans")
async def get_scan_history():
    """Retrieve full scan execution history with stages and timestamps."""
    return list(reversed(SCANNER.scan_history))

@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    scan = next((s for s in SCANNER.scan_history if s["scan_id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found.")
    return scan

# Auditor Finding Triage Endpoints (ref_1.md Module F3)
@app.get("/api/findings")
async def get_findings(status: Optional[str] = Query(None)):
    """Retrieve findings with human auditor review status (PENDING / APPROVED / REJECTED)."""
    return GLOBAL_TRIAGE_MANAGER.get_findings(status_filter=status)

@app.post("/api/findings/{finding_id}/triage")
async def triage_finding(finding_id: str, req: TriageRequest):
    """Auditor updates finding status with review notes."""
    try:
        updated = GLOBAL_TRIAGE_MANAGER.triage_finding(
            finding_id=finding_id,
            new_status=req.status,
            auditor_notes=req.auditor_notes or "",
            reviewer=req.reviewer or "Security Auditor"
        )
        if not updated:
            raise HTTPException(status_code=404, detail="Finding ID not found.")
        return updated
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/findings/stats")
async def get_triage_stats():
    return GLOBAL_TRIAGE_MANAGER.get_triage_stats()

# Webhook Alert Dispatcher Configuration (ref_1.md Module G3)
@app.get("/api/config/webhook")
async def get_webhook_config():
    return GLOBAL_ALERT_DISPATCHER.get_status()

@app.post("/api/config/webhook")
async def configure_webhook(req: WebhookConfigRequest):
    GLOBAL_ALERT_DISPATCHER.configure(req.webhook_url, req.enabled)
    return {"status": "configured", "details": GLOBAL_ALERT_DISPATCHER.get_status()}

class CveSyncRequest(BaseModel):
    reload_only: bool = True
    custom_cve: Optional[Dict[str, Any]] = None

# CVE Multi-Feed Management & Scale-up Endpoints
@app.get("/api/cve/database")
async def get_cve_database():
    """Return all loaded CVE definitions and multi-feed diagnostics."""
    return {
        "status": "success",
        "summary": GLOBAL_CVE_MANAGER.get_feeds_summary(),
        "cves": GLOBAL_CVE_MANAGER.get_all_cves()
    }

@app.post("/api/cve/sync")
async def sync_cve_database(req: Optional[CveSyncRequest] = None):
    """Hot-reload multi-feed vulnerability database and optionally register custom scale-up CVEs."""
    if req and req.custom_cve:
        GLOBAL_CVE_MANAGER.register_custom_cve(req.custom_cve, persist=True)
    reloaded_count = GLOBAL_CVE_MANAGER.reload_feeds()
    return {
        "status": "success",
        "reloaded_cve_count": reloaded_count,
        "summary": GLOBAL_CVE_MANAGER.get_feeds_summary()
    }

@app.post("/api/cve/evaluate")
async def evaluate_cve_for_device(device_payload: Dict[str, Any]):
    """Ad-hoc contextual evaluation for a device dictionary without scanning network."""
    matched_raw = match_cves_for_device(device_payload)
    context_eval = evaluate_device_context(device_payload, matched_raw)
    return {
        "device_summary": {
            "vendor": device_payload.get("vendor"),
            "model": device_payload.get("model"),
            "open_ports": device_payload.get("open_ports", [])
        },
        "matched_cves": context_eval["evaluated_cves"],
        "highest_ssvc_action": context_eval["highest_ssvc_action"],
        "active_exploitable_count": context_eval["active_exploitable_count"],
        "mitigated_count": context_eval["mitigated_count"],
        "quarantine_mandated": context_eval["quarantine_mandated"],
        "can_live_with_all": context_eval["can_live_with_all"]
    }

# Inventory & Scoping Endpoints
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
    """Generates an academic-grade governance audit report including CPEs, policies, and triage."""
    stats = SCANNER.get_summary_statistics()
    devices = [d for d in SCANNER.inventory.values() if is_edge_ip(d.get("ip", ""))]
    triage_stats = stats.get("triage", {})

    lines = [
        "# IoT Cybersecurity Audit & Governance Report",
        f"**Course**: IT6027 - Cybersecurity Policy and Governance",
        f"**Audit Timestamp**: {SCANNER.last_scan_time or 'N/A'}",
        f"**Active Scan ID**: {SCANNER.current_scan_id or 'N/A'}",
        f"**Total Devices Audited**: {stats['total_devices']}",
        f"**High/Critical Insecure Devices**: {stats['vulnerable_devices']}",
        f"**Default Passwords Discovered**: {stats['default_passwords_found']}",
        f"**Devices Recommended for Quarantine**: {stats['quarantine_recommended']}",
        f"**Auditor Verified Violations**: {triage_stats.get('approved_violations', 0)} (Approved) / {triage_stats.get('pending_review', 0)} (Pending)",
        "",
        "---",
        "",
        "## 1. Executive Summary & Policy Compliance",
        "This assessment evaluated the operational IoT edge network against cybersecurity baselines (NIST IR 8259A & ETSI EN 303 645):",
        "- **Device Fingerprinting via Banner/mDNS/UPnP**: Mandatory component executed across all active hosts.",
        "- **Firmware / CVE Matching with CPE 2.3 Normalization**: Standardized device banners to NIST CPE 2.3 URIs and matched known CVEs.",
        "- **Default Credential Auditing**: Tested authentication endpoints against dictionary wordlists.",
        "- **Declarative Policy Engine & VLAN Scoping**: Applied YAML hardening rules and recommended quarantine actions for compromised endpoints.",
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
    lines.append("## 3. Discovered Vulnerabilities & CVE Details (with CPE Identifiers)")
    found_cves = False
    for d in devices:
        for cve in d.get("cves", []):
            found_cves = True
            cpe_tag = f" (`{cve.get('cpe')}`)" if cve.get("cpe") else ""
            vex_info = f" | VEX: **{cve.get('vex_status', 'AFFECTED')}** ({cve.get('exploitability', 'ACTIVE_EXPLOITABLE')}) | SSVC Action: **{cve.get('ssvc_action', 'ATTEND')}**" if cve.get('vex_status') else ""
            lines.append(f"### {cve['cve_id']}: {cve['title']}{cpe_tag}")
            lines.append(f"- **Target IP**: `{d['ip']}` ({d['device_type']})")
            lines.append(f"- **Risk & Prioritization**: CVSS {cve['cvss_score']} ({cve['severity']}){vex_info}")
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

    lines.append("")
    lines.append("## 5. Auditor Triage & Verification Sign-Off")
    findings = GLOBAL_TRIAGE_MANAGER.get_findings()
    if findings:
        for f in findings:
            rev_info = f" (Reviewed by: {f['reviewed_by']})" if f['reviewed_by'] else ""
            notes = f" - Notes: {f['auditor_notes']}" if f['auditor_notes'] else ""
            lines.append(f"- **[{f['status']}]** `{f['target_ip']}` - {f['title']}{rev_info}{notes}")
    else:
        lines.append("No individual findings logged for review.")

    return HTMLResponse("<pre style='white-space: pre-wrap; font-family: monospace;'>" + "\n".join(lines) + "</pre>")
