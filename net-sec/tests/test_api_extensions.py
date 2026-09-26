"""
Integration Tests for Platform Web API Extensions (net-sec)
Verifies Scope Management API, Auditor Triage API, Scan History, and Webhook Config.
"""

import pytest
from fastapi.testclient import TestClient
from app.web.api import app
from app.audit.triage import GLOBAL_TRIAGE_MANAGER

@pytest.fixture
def client():
    return TestClient(app)

def test_api_scope_check_authorized(client):
    res = client.get("/api/scope/check?cidr=192.168.137.0/24")
    assert res.status_code == 200
    data = res.json()
    assert data["allowed"] is True
    assert "Hotspot" in data["vlan_name"]

def test_api_scope_check_rejected(client):
    res = client.get("/api/scope/check?cidr=8.8.8.0/24")
    assert res.status_code == 200
    data = res.json()
    assert data["allowed"] is False
    assert "Scope Violation" in data["reason"]

def test_api_scope_allowed_list(client):
    res = client.get("/api/scope/allowed")
    assert res.status_code == 200
    scopes = res.json()
    assert len(scopes) >= 3
    assert any(s["cidr"] == "192.168.137.0/24" for s in scopes)

def test_api_findings_and_triage(client):
    # Record a test finding
    finding = GLOBAL_TRIAGE_MANAGER.record_finding(
        target_ip="192.168.137.99",
        finding_type="POLICY_VIOLATION",
        title="Telnet Cleartext Test",
        severity="HIGH",
        details="Port 23 open without encryption",
        rule_id="IOT-POL-003"
    )

    # 1. Fetch findings
    res = client.get("/api/findings")
    assert res.status_code == 200
    findings = res.json()
    assert any(f["finding_id"] == finding.finding_id for f in findings)

    # 2. Triage finding to APPROVED
    triage_res = client.post(
        f"/api/findings/{finding.finding_id}/triage",
        json={"status": "APPROVED", "auditor_notes": "Confirmed true positive in lab", "reviewer": "Auditor Dave"}
    )
    assert triage_res.status_code == 200
    up = triage_res.json()
    assert up["status"] == "APPROVED"
    assert up["auditor_notes"] == "Confirmed true positive in lab"

def test_api_scan_history(client):
    res = client.get("/api/scans")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_api_webhook_config(client):
    res = client.get("/api/config/webhook")
    assert res.status_code == 200
    cfg = res.json()
    assert "enabled" in cfg

    post_res = client.post("/api/config/webhook", json={"webhook_url": "https://example.com/webhook", "enabled": True})
    assert post_res.status_code == 200
    assert post_res.json()["status"] == "configured"

def test_api_governance_report_output(client):
    res = client.get("/api/report")
    assert res.status_code == 200
    assert "IoT Cybersecurity Audit & Governance Report" in res.text
    assert "IT6027" in res.text
