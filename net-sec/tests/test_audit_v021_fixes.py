"""
Regression and Verification Tests for v0.2.1 Audit & Performance Fixes
Course: IT6027 - Cybersecurity Policy and Governance
"""

import pytest
import asyncio
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import time

from app.audit.cve_matcher import match_cves_for_device
from app.scoping.scope_service import GLOBAL_SCOPE_MANAGER, ScopeManager
from app.scoping.vlan_scoper import resolve_vlan_for_ip
from app.scanner_engine import SecurityScannerEngine

def test_cve_matcher_patched_version_not_matched_by_fallback():
    """
    Verify that a patched firmware version (e.g. DCS-932L with version 2.5.0)
    is NOT matched by Fallback 2 (vendor+product keyword match).
    CVE-2020-25078 affects D-Link DCS-932L firmware up to 1.14.04 (or 1.0.1).
    """
    device_patched = {
        "vendor": "D-Link Systems",
        "model": "DCS-932L",
        "firmware": "2.5.0",
        "banners": {
            "http_8080": {
                "server": "GoAhead-Webs/2.5.0",
                "auth_realm": 'Basic realm="D-Link DCS-932L"'
            }
        }
    }
    matched = match_cves_for_device(device_patched)
    # CVE-2020-25078 has version_end_including: "1.14.04". Version 2.5.0 is out of bounds!
    assert not any(c["cve_id"] == "CVE-2020-25078" for c in matched)

def test_scope_service_is_ip_in_scope_allows_loopback_nodes():
    """Verify is_ip_in_scope allows 127.0.0.2 while strictly rejecting 127.0.0.1 and WAN."""
    assert GLOBAL_SCOPE_MANAGER.is_ip_in_scope("127.0.0.2") is True
    assert GLOBAL_SCOPE_MANAGER.is_ip_in_scope("127.0.0.5") is True
    assert GLOBAL_SCOPE_MANAGER.is_ip_in_scope("127.0.0.1") is False
    assert GLOBAL_SCOPE_MANAGER.is_ip_in_scope("8.8.8.8") is False

def test_vlan_scoper_resolves_loopback_mock_to_vlan_10():
    """Verify resolve_vlan_for_ip accurately maps loopback mock nodes to VLAN 10."""
    vlan = resolve_vlan_for_ip("127.0.0.2")
    assert vlan["vlan_id"] == 10
    assert "Local IoT Testbed Emulation" in vlan["name"]

def test_loopback_host_not_marked_alive_via_icmp_when_ports_closed():
    """
    Verify that check_host_alive returns False for a loopback IP where no ports are open,
    preventing false-positive alive states from OS kernel ICMP echo responses.
    """
    engine = SecurityScannerEngine()
    # 127.0.0.99 has no services running
    alive = engine.check_host_alive("127.0.0.99", open_ports=[])
    assert alive is False

def test_presence_monitor_detects_mock_loopback(monkeypatch):
    """Verify that presence_check_cycle discovers active loopback mock nodes without ARP."""
    class DummyCameraHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Server", "GoAhead-Webs/2.5")
            self.end_headers()
            self.wfile.write(b"OK")
        def log_message(self, format, *args):
            return

    server = HTTPServer(("127.0.0.2", 18088), DummyCameraHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)

    try:
        engine = SecurityScannerEngine()
        # Mock scan_single_device to return quick dummy record
        async def mock_scan(ip, mac=""):
            return {
                "ip": ip,
                "mac": mac,
                "device_type": "IP Camera",
                "vendor": "D-Link Systems",
                "open_ports": [18088],
                "banners": {"http_18088": {"server": "GoAhead-Webs/2.5"}},
                "is_online": True
            }
        monkeypatch.setattr(engine, "scan_single_device", mock_scan)
        monkeypatch.setattr(engine, "get_arp_hosts", lambda edge_only=True: {})

        # Simulate presence check cycle
        # Mock port probe for 127.0.0.2 to return port open
        import socket
        orig_connect_ex = socket.socket.connect_ex
        def fake_connect_ex(sock_self, addr):
            if addr[0] == "127.0.0.2" and addr[1] == 80:
                return 0
            return orig_connect_ex(sock_self, addr)

        monkeypatch.setattr(socket.socket, "connect_ex", fake_connect_ex)

        engine.presence_check_cycle()

        assert "127.0.0.2" in engine.inventory
        assert engine.inventory["127.0.0.2"]["is_online"] is True
        assert len(engine.alerts) >= 1
    finally:
        server.shutdown()
        server.server_close()
