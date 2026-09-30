"""
Comprehensive Unit & Integration Tests for Advanced CVE Lifecycle (v0.2.0)
Validates tripartite CPE 2.3 normalizer, multi-feed CVE manager,
contextual prioritization (Rules A, B, C with CISA SSVC and VEX),
and scale-up synchronization.
"""

import pytest
from fastapi.testclient import TestClient
from app.audit.cpe_normalizer import CpeNormalizer, compare_versions
from app.audit.cve_manager import CveManager, GLOBAL_CVE_MANAGER
from app.audit.cve_matcher import match_cves_for_device
from app.audit.contextual_prioritizer import evaluate_cve_context, evaluate_device_context
from app.audit.triage import GLOBAL_TRIAGE_MANAGER
from app.web.api import app

client = TestClient(app)

# -----------------------------------------------------------------------------
# 1. Tripartite CPE 2.3 Generation Tests
# -----------------------------------------------------------------------------
def test_tripartite_cpe_generation():
    device = {
        "vendor": "D-Link Systems",
        "model": "DCS-932L",
        "firmware": "1.0.1",
        "banners": {
            "http_8080": {"server": "GoAhead-Webs/2.5.0"}
        }
    }
    candidates = CpeNormalizer.extract_cpe_candidates(device)
    parts = {c["part"] for c in candidates}
    
    # Must emit all three tiers: 'h' (hardware), 'o' (firmware), 'a' (application)
    assert "h" in parts, "Missing hardware CPE candidate"
    assert "o" in parts, "Missing firmware CPE candidate"
    assert "a" in parts, "Missing application CPE candidate"

    hw = next(c for c in candidates if c["part"] == "h")
    assert hw["vendor"] == "dlink"
    assert hw["product"] == "dcs-932l"

    fw = next(c for c in candidates if c["part"] == "o")
    assert fw["vendor"] == "dlink"
    assert fw["version"] == "1.0.1"

    app = next(c for c in candidates if c["part"] == "a")
    assert app["vendor"] == "embedthis"
    assert app["version"] == "2.5.0"

def test_cpe_alias_denoising():
    """Verify alias dictionary denoises fragmented strings."""
    assert CpeNormalizer.build_cpe_uri("h", "D-Link Corporation", "DCS-932L").startswith("cpe:2.3:h:dlink:")
    assert CpeNormalizer.build_cpe_uri("a", "Hangzhou Xiongmai", "uc-httpd").startswith("cpe:2.3:a:xiongmai:")
    assert CpeNormalizer.build_cpe_uri("h", "Espressif Systems", "ESP32").startswith("cpe:2.3:h:espressif:esp32:")
    assert CpeNormalizer.build_cpe_uri("a", "Mobile Device (IP Webcam)", "IP Webcam Server").startswith("cpe:2.3:a:ip_webcam_project:")

# -----------------------------------------------------------------------------
# 2. Semantic Version Range Boundary Tests
# -----------------------------------------------------------------------------
def test_semver_range_boundaries():
    # Target in range [1.0.0, 1.14.04]
    assert compare_versions("1.0.1", version_start_including="1.0.0", version_end_including="1.14.04") is True
    assert compare_versions("1.14.04", version_start_including="1.0.0", version_end_including="1.14.04") is True
    assert compare_versions("1.0.0", version_start_including="1.0.0", version_end_including="1.14.04") is True
    
    # Target patched (out of bounds)
    assert compare_versions("1.14.05", version_start_including="1.0.0", version_end_including="1.14.04") is False
    assert compare_versions("2.0.0", version_start_including="1.0.0", version_end_including="1.14.04") is False
    assert compare_versions("0.9.9", version_start_including="1.0.0", version_end_including="1.14.04") is False

# -----------------------------------------------------------------------------
# 3. Scalable Multi-Feed CVE Manager Tests
# -----------------------------------------------------------------------------
def test_multi_feed_manager_and_scale_up():
    mgr = CveManager()
    summary = mgr.get_feeds_summary()
    assert summary["total_feeds"] >= 2
    assert summary["total_cves"] >= 8

    # Simulate network scale-up: Register custom ESP32 IoT sensor CVE
    custom_cve = {
        "cve_id": "CVE-2026-ESP32-TEST",
        "title": "Custom ESP32 Test Sensor Overflow",
        "target_cpe_list": ["cpe:2.3:h:espressif:esp32:*:*:*:*:*:*:*:*"],
        "required_open_ports": [80],
        "cvss_score": 8.5,
        "severity": "HIGH",
        "description": "Test vulnerability for custom ESP32 IoT sensor.",
        "remediation": "Flash updated firmware binary."
    }
    success = mgr.register_custom_cve(custom_cve, persist=False)
    assert success is True
    assert mgr.get_cve_by_id("CVE-2026-ESP32-TEST") is not None

# -----------------------------------------------------------------------------
# 4. Contextual Prioritization Tests (Rules A, B, C)
# -----------------------------------------------------------------------------
def test_rule_a_port_closed_safe_to_live_with():
    """Rule A: Required port closed -> TRACK / VEX: NOT_AFFECTED."""
    device = {
        "ip": "172.28.10.50",
        "open_ports": [22],  # Port 80/8080 CLOSED
        "default_credentials_found": False,
        "vlan": {"id": 10}
    }
    cve = {
        "cve_id": "CVE-2020-25078",
        "title": "D-Link Config Disclosure",
        "required_open_ports": [80, 8080],
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": False
    }
    res = evaluate_cve_context(device, cve)
    assert res["vex_status"] == "NOT_AFFECTED"
    assert res["exploitability"] == "MITIGATED_SERVICE_DISABLED"
    assert res["ssvc_action"] == "TRACK"
    assert res["can_live_with"] is True
    assert res["threat_level"] == "NEGLIGIBLE"

def test_rule_b_compensating_quarantine_vlan():
    """Rule B: Device already in Quarantine VLAN 99 -> ATTEND."""
    device = {
        "ip": "172.28.99.10",
        "open_ports": [80],
        "default_credentials_found": False,
        "vlan": {"id": 99, "name": "Quarantine"}
    }
    cve = {
        "cve_id": "CVE-2022-26325",
        "title": "Camera Telemetry Disclosure",
        "required_open_ports": [80],
        "cvss_score": 7.5,
        "severity": "HIGH",
        "cisa_kev": False
    }
    res = evaluate_cve_context(device, cve)
    assert res["vex_status"] == "AFFECTED"
    assert res["exploitability"] == "MITIGATED_ISOLATED_VLAN"
    assert res["ssvc_action"] == "ATTEND"
    assert res["threat_level"] == "LOW"

def test_rule_c_active_weaponization_mandates_quarantine():
    """Rule C: CISA KEV or Critical CVSS on open port -> ACT (Quarantine)."""
    device = {
        "ip": "172.28.10.20",
        "open_ports": [8080],
        "default_credentials_found": True,
        "vlan": {"id": 10}
    }
    cve = {
        "cve_id": "CVE-2020-25078",
        "title": "D-Link Config Disclosure",
        "required_open_ports": [80, 8080],
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": True
    }
    res = evaluate_cve_context(device, cve)
    assert res["vex_status"] == "AFFECTED"
    assert res["exploitability"] == "ACTIVE_EXPLOITABLE"
    assert res["ssvc_action"] == "ACT"
    assert res["can_live_with"] is False
    assert res["threat_level"] == "CRITICAL"

    dev_eval = evaluate_device_context(device, [cve])
    assert dev_eval["quarantine_mandated"] is True
    assert dev_eval["highest_ssvc_action"] == "ACT"

# -----------------------------------------------------------------------------
# 5. Web API CVE Endpoints Tests
# -----------------------------------------------------------------------------
def test_api_cve_endpoints():
    # GET database
    resp = client.get("/api/cve/database")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["summary"]["total_cves"] >= 8

    # POST sync
    resp_sync = client.post("/api/cve/sync", json={"reload_only": True})
    assert resp_sync.status_code == 200
    assert resp_sync.json()["status"] == "success"

    # POST evaluate
    test_device = {
        "vendor": "D-Link Systems",
        "model": "DCS-932L",
        "firmware": "1.0.1",
        "open_ports": [8080],
        "banners": {"http_8080": {"server": "GoAhead-Webs/2.5.0"}}
    }
    resp_eval = client.post("/api/cve/evaluate", json=test_device)
    assert resp_eval.status_code == 200
    eval_res = resp_eval.json()
    assert len(eval_res["matched_cves"]) >= 1
    assert any(c["cve_id"] == "CVE-2020-25078" for c in eval_res["matched_cves"])
    assert eval_res["highest_ssvc_action"] in ["ACT", "ATTEND"]

# -----------------------------------------------------------------------------
# 6. Triage Record VEX & SSVC Verification
# -----------------------------------------------------------------------------
def test_triage_vex_fields():
    rec = GLOBAL_TRIAGE_MANAGER.record_finding(
        target_ip="192.168.137.50",
        finding_type="CVE",
        title="CVE-2020-25078: Test Disclosure",
        severity="CRITICAL",
        details="Test exploitability details",
        vex_status="AFFECTED",
        vex_justification="ACTIONABLE_EXPLOIT_AVAILABLE",
        exploitability="ACTIVE_EXPLOITABLE",
        ssvc_action="ACT"
    )
    assert rec.vex_status == "AFFECTED"
    assert rec.ssvc_action == "ACT"
    d = rec.to_dict()
    assert d["vex_status"] == "AFFECTED"
    assert d["ssvc_action"] == "ACT"
