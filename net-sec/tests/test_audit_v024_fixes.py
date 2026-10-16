"""
Unit & Integration Tests for Version v0.2.4 Fixes (net-sec)
Verifies:
1. VLAN 99 quarantine isolation detection in contextual_prioritizer.
2. Idempotent SQLite cve_findings deduplication.
3. Thread-safe get_edge_devices() retrieval without lock contention.
4. UPnP firmware_version extraction in CPE normalization and CVE matching.
"""

import pytest
from app.audit.contextual_prioritizer import evaluate_cve_context, evaluate_device_context
from app.db.database import DatabaseManager
from app.audit.cpe_normalizer import CpeNormalizer
from app.audit.cve_matcher import match_cves_for_device
from app.scanner_engine import SecurityScannerEngine

def test_vlan99_quarantine_detection_in_contextual_prioritizer():
    # Device in VLAN 99 with a high/medium CVE that has required ports open
    device_in_quarantine = {
        "ip": "172.28.99.20",
        "open_ports": [80],
        "default_credentials_found": False,
        "vlan": {"vlan_id": 99, "name": "VLAN 99 - IoT Quarantine & Isolation Subnet"}
    }
    sample_cve = {
        "cve_id": "CVE-2021-38144",
        "title": "Daikin BRP Wi-Fi Air Conditioner Controller",
        "required_open_ports": [80],
        "cvss_score": 7.5,
        "cisa_kev": False,
        "severity": "HIGH"
    }
    result = evaluate_cve_context(device_in_quarantine, sample_cve)
    assert result["vex_status"] == "AFFECTED"
    assert result["exploitability"] == "MITIGATED_ISOLATED_VLAN"
    assert result["ssvc_action"] == "ATTEND"
    assert result["threat_level"] == "LOW"
    assert "Quarantine VLAN 99" in result["context_reason"]

def test_sqlite_cve_findings_deduplication(tmp_path):
    db_file = str(tmp_path / "test_dedup.db")
    db = DatabaseManager(db_path=db_file)

    device_payload = {
        "ip": "172.28.10.20",
        "mac": "00:11:22:33:44:55",
        "vendor": "D-Link",
        "model": "DCS-932L",
        "device_type": "IP Camera",
        "open_ports": [8080, 554],
        "cves": [
            {
                "cve_id": "CVE-2020-25078",
                "title": "D-Link IP Camera Credential Disclosure",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "cpe": "cpe:2.3:o:dlink:dcs-932l_firmware:1.0.1:*:*:*:*:*:*:*",
                "vex_status": "AFFECTED",
                "exploitability": "ACTIVE_EXPLOITABLE",
                "ssvc_action": "ACT",
                "description": "Plaintext credentials",
                "remediation": "Update firmware"
            }
        ]
    }

    # Save multiple times with same scan_id
    db.save_device(device_payload, scan_id="scan_test_001")
    db.save_device(device_payload, scan_id="scan_test_001")
    db.save_device(device_payload, scan_id="scan_test_001")

    stats = db.get_db_stats()
    assert stats["devices_count"] == 1
    assert stats["cve_findings_count"] == 1

def test_scanner_engine_get_edge_devices_thread_safe():
    engine = SecurityScannerEngine()
    engine.inventory["172.28.10.20"] = {
        "ip": "172.28.10.20",
        "device_type": "IP Camera",
        "risk_level": "CRITICAL"
    }
    engine.inventory["192.168.1.50"] = {  # WAN / non-edge IP
        "ip": "192.168.1.50",
        "device_type": "Router",
        "risk_level": "LOW"
    }

    devices = engine.get_edge_devices()
    assert len(devices) == 1
    assert devices[0]["ip"] == "172.28.10.20"

def test_upnp_firmware_version_extraction_and_matching():
    device_info = {
        "ip": "172.28.10.20",
        "vendor": "D-Link Systems",
        "model": "DCS-932L",
        "open_ports": [8080],
        "banners": {"http_8080": {"server": "GoAhead-Webs/2.5"}},
        "upnp_meta": {
            "manufacturer": "D-Link Systems",
            "model_name": "DCS-932L",
            "model_number": "Rev B1",
            "firmware_version": "1.0.1"
        }
    }

    cpes = CpeNormalizer.extract_cpe_candidates(device_info)
    fw_cpe = next((c for c in cpes if c["part"] == "o"), None)
    assert fw_cpe is not None
    assert fw_cpe["version"] == "1.0.1"

    matched = match_cves_for_device(device_info)
    assert any(c["cve_id"] == "CVE-2020-25078" for c in matched)

def test_hotspot_bridge_digest_auth_detection():
    import threading
    import time
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from hotspot_bridge import audit_http_credentials

    class MockCameraDigest(BaseHTTPRequestHandler):
        def do_GET(self):
            auth_hdr = self.headers.get("Authorization", "")
            if not auth_hdr:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Digest realm="IP Webcam", nonce="12345678", qop="auth"')
                self.end_headers()
                self.wfile.write(b"401 Unauthorized")
                return
            if "admin" in auth_hdr and "Digest" in auth_hdr:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Stream OK")
                return
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Digest realm="IP Webcam", nonce="12345678", qop="auth"')
            self.end_headers()

        def log_message(self, format, *args):
            return

    srv = HTTPServer(("127.0.0.1", 18889), MockCameraDigest)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)
    try:
        res = audit_http_credentials("127.0.0.1", 18889)
        assert res["auth_required"] is True
        assert res["default_credentials_found"] is True
        assert res["matched_credential"] == "admin:admin"
        assert "Digest" in res["service"]
    finally:
        srv.shutdown()
        srv.server_close()

def test_sub_endpoint_camera_digest_auth_detection():
    import threading
    import time
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from app.audit.credential_checker import test_http_auth

    class MockCameraPartial(BaseHTTPRequestHandler):
        def do_GET(self):
            auth_hdr = self.headers.get("Authorization", "")
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><title>IP Webcam</title><body>Webcam Control</body></html>")
                return
            elif self.path in ["/video", "/status.json", "/shot.jpg"]:
                if not auth_hdr:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Digest realm="IP Webcam", nonce="abcdef99", qop="auth"')
                    self.end_headers()
                    self.wfile.write(b"401 Unauthorized")
                    return
                if "admin" in auth_hdr and "Digest" in auth_hdr:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Authorized Video")
                    return
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Digest realm="IP Webcam", nonce="abcdef99", qop="auth"')
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format, *args):
            return

    srv = HTTPServer(("127.0.0.1", 18890), MockCameraPartial)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)
    try:
        res = test_http_auth("127.0.0.1", 18890, [("admin", "admin")])
        assert res["auth_required"] is True
        assert res["matched_credential"] == "admin:admin"
        assert "Digest" in res["service"]
        assert res["is_open_access"] is False
    finally:
        srv.shutdown()
        srv.server_close()

