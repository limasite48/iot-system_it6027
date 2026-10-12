"""
Unit Tests for SQLite Persistence Layer & Database Schema Compliance
Course: IT6027 - Cybersecurity Policy and Governance
Tests DDL initialization, scan session tracking, device upserting,
auditor triage ledger, alert persistence, and startup restoration.
"""

import os
import pytest
from app.db.database import DatabaseManager
from app.scanner_engine import SecurityScannerEngine
from app.audit.triage import AuditorTriageManager
from fastapi.testclient import TestClient
from app.web.api import app

@pytest.fixture
def temp_db(tmp_path):
    """Fixture providing an isolated temporary SQLite database."""
    db_file = os.path.join(tmp_path, "test_iot.db")
    mgr = DatabaseManager(db_path=db_file)
    return mgr

def test_database_initialization(temp_db):
    """Verify all 6 relational schema tables and indices are initialized properly."""
    stats = temp_db.get_db_stats()
    assert stats["scans_count"] == 0
    assert stats["devices_count"] == 0
    assert stats["ports_count"] == 0
    assert stats["cve_findings_count"] == 0
    assert stats["triage_records_count"] == 0
    assert stats["alerts_count"] == 0

def test_save_and_load_scan(temp_db):
    """Verify scan orchestration sessions are stored and retrievable."""
    scan_data = {
        "scan_id": "scan_test_001",
        "target_cidr": "172.28.10.0/24",
        "start_time": "2026-10-12T10:00:00",
        "end_time": "2026-10-12T10:00:15",
        "status": "COMPLETED",
        "stage": "STAGE_7_COMPLETED",
        "devices_discovered": 4
    }
    temp_db.save_scan(scan_data)
    
    history = temp_db.load_scan_history()
    assert len(history) == 1
    assert history[0]["scan_id"] == "scan_test_001"
    assert history[0]["devices_discovered"] == 4
    assert history[0]["status"] == "COMPLETED"

def test_save_and_load_device(temp_db):
    """Verify device cataloging, open ports, and correlated CVEs are relational-stored."""
    dev_data = {
        "ip": "172.28.10.20",
        "mac": "00:11:22:33:44:55",
        "vendor": "D-Link",
        "model": "DCS-932L",
        "device_type": "IP Camera",
        "vlan": {"vlan_id": 10, "name": "VLAN 10 - Standard IoT"},
        "risk_level": "CRITICAL",
        "default_credentials_found": True,
        "is_open_access": False,
        "is_online": True,
        "open_ports": [80, 554],
        "banners": {"80": "GoAhead-Webs/2.5", "554": "RTSP/1.0"},
        "cves": [
            {
                "cve_id": "CVE-2020-25078",
                "title": "D-Link Credentials Disclosure",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "cpe": "cpe:2.3:o:dlink:dcs-932l_firmware:1.14:*:*:*:*:*:*:*",
                "vex_status": "AFFECTED",
                "exploitability": "ACTIVE_EXPLOITABLE",
                "ssvc_action": "ACT",
                "description": "Information disclosure in /common/info.cgi",
                "remediation": "Update firmware or isolate in VLAN 99"
            }
        ],
        "last_audited": "2026-10-12T10:05:00"
    }

    temp_db.save_device(dev_data, scan_id="scan_test_001")

    # Load devices back
    loaded = temp_db.load_all_devices()
    assert "172.28.10.20" in loaded
    rec = loaded["172.28.10.20"]
    assert rec["vendor"] == "D-Link"
    assert rec["risk_level"] == "CRITICAL"
    assert rec["default_credentials_found"] is True

    # Check relational table statistics
    stats = temp_db.get_db_stats()
    assert stats["devices_count"] == 1
    assert stats["ports_count"] == 2
    assert stats["cve_findings_count"] == 1

def test_save_and_update_triage_finding(temp_db):
    """Verify auditor triage records transition states and persist notes."""
    finding = {
        "finding_id": "fnd_test_100",
        "target_ip": "172.28.10.20",
        "finding_type": "CVE",
        "title": "CVE-2020-25078 Credentials Disclosure",
        "severity": "CRITICAL",
        "port": 80,
        "cve_id": "CVE-2020-25078",
        "status": "PENDING",
        "auditor_notes": "",
        "reviewed_by": "",
        "details": "Exposed credential URL",
        "remediation": "Quarantine"
    }
    temp_db.save_triage_finding(finding)

    records = temp_db.load_all_triage_findings()
    assert len(records) == 1
    assert records[0]["status"] == "PENDING"

    # Auditor signs off: APPROVED
    finding["status"] = "APPROVED"
    finding["auditor_notes"] = "Verified in lab environment; mandatory VLAN 99 quarantine"
    finding["reviewed_by"] = "Lead Auditor Alice"
    finding["reviewed_at"] = "2026-10-12T10:10:00"
    temp_db.save_triage_finding(finding)

    updated_records = temp_db.load_all_triage_findings()
    assert len(updated_records) == 1
    assert updated_records[0]["status"] == "APPROVED"
    assert "Alice" in updated_records[0]["reviewed_by"]
    assert "quarantine" in updated_records[0]["auditor_notes"]

def test_save_and_load_alerts(temp_db):
    """Verify security alert persistence."""
    alert = {
        "timestamp": "2026-10-12T10:02:00",
        "severity": "CRITICAL",
        "device_ip": "172.28.10.20",
        "device_type": "IP Camera",
        "title": "Default Password Alert (admin:admin)",
        "details": "Port 80 accepted factory login"
    }
    temp_db.save_alert(alert)

    alerts = temp_db.load_recent_alerts()
    assert len(alerts) == 1
    assert alerts[0]["device_ip"] == "172.28.10.20"
    assert alerts[0]["severity"] == "CRITICAL"

def test_scanner_engine_persistence_integration(temp_db):
    """Verify SecurityScannerEngine restores inventory from SQLite on startup."""
    dev_data = {
        "ip": "172.28.10.25",
        "mac": "02:00:7D:00:00:25",
        "vendor": "Sony",
        "model": "BRAVIA TV",
        "device_type": "Smart TV",
        "risk_level": "LOW",
        "default_credentials_found": False,
        "is_online": True,
        "last_audited": "2026-10-12T10:00:00"
    }
    temp_db.save_device(dev_data)

    # Initialize a new scanner engine pointing to this DB
    engine = SecurityScannerEngine(db_manager=temp_db, auto_load=True)
    assert "172.28.10.25" in engine.inventory
    assert engine.inventory["172.28.10.25"]["vendor"] == "Sony"

def test_triage_manager_persistence_integration(temp_db):
    """Verify AuditorTriageManager restores findings and updates them into DB."""
    triage_mgr = AuditorTriageManager(db_manager=temp_db)
    rec = triage_mgr.record_finding(
        target_ip="172.28.10.30",
        finding_type="DEFAULT_CREDENTIAL",
        title="Port 80: admin:admin",
        severity="CRITICAL",
        details="Default password accepted"
    )

    assert rec.status == "PENDING"
    # Verify persisted in DB
    db_findings = temp_db.load_all_triage_findings()
    assert len(db_findings) == 1

    # Triage via manager
    triage_mgr.triage_finding(rec.finding_id, new_status="APPROVED", auditor_notes="Confirmed breach risk")

    # Restart manager with same DB
    restarted_mgr = AuditorTriageManager(db_manager=temp_db, auto_load=True)
    restarted_findings = restarted_mgr.get_findings()
    assert len(restarted_findings) == 1
    assert restarted_findings[0]["status"] == "APPROVED"
    assert restarted_findings[0]["auditor_notes"] == "Confirmed breach risk"

def test_api_db_stats():
    """Verify GET /api/db/stats returns valid schema statistics."""
    client = TestClient(app)
    resp = client.get("/api/db/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "scans_count" in data
    assert "devices_count" in data
    assert "ports_count" in data
    assert "cve_findings_count" in data
    assert "triage_records_count" in data
