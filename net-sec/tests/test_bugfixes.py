"""
Unit & Integration Tests for System Bugfixes & Enhancements
Verifies:
1. Stale / Ghost ARP lease suppression (dead device with 0 open ports not added to inventory)
2. Open access / no password risk escalation (CRITICAL & quarantine)
3. Dynamic network adapter and subnet detection
4. Smartphone & Private MAC classification accuracy
"""

import pytest
import asyncio
from app.scanner_engine import SecurityScannerEngine
from app.scoping.classifier import classify_device
from app.scoping.vlan_scoper import evaluate_scoping_policy
from app.discovery.network_env import (
    detect_active_subnets,
    get_primary_edge_cidr,
    get_host_ips,
    get_hotspot_active_clients,
    is_edge_ip
)

def test_dynamic_network_env():
    """Verify that network subnets and primary CIDR are detected dynamically without crash."""
    subnets = detect_active_subnets()
    assert isinstance(subnets, list)
    primary = get_primary_edge_cidr()
    assert isinstance(primary, str)
    assert "/" in primary
    host_ips = get_host_ips()
    assert "127.0.0.1" in host_ips

def test_open_access_escalation_to_critical_and_quarantine():
    """Verify that unauthenticated open access (no password) triggers CRITICAL risk and quarantine."""
    dev = {
        "ip": "192.168.137.155",
        "default_credentials_found": False,
        "is_open_access": True,
        "cves": []
    }
    policy = evaluate_scoping_policy(dev)
    assert policy["risk_level"] == "CRITICAL"
    assert policy["quarantine_required"] is True
    assert policy["policy_violation"] is True
    assert "Unauthenticated open access" in policy["policy_message"]
    assert "VLAN 99" in policy["recommended_vlan"]

def test_smartphone_with_private_mac_classification():
    """Verify smartphone with randomized MAC is classified as Smartphone or IP Camera when streaming."""
    # Scenario A: Smartphone with IP Webcam banner on port 8080
    dev_cam = {
        "open_ports": [8080],
        "banners": {8080: {"title": "IP Webcam"}},
        "vendor": "Randomized / Private MAC (Mobile Device)",
        "model": "Xiaomi-12S-Pro",
        "upnp_meta": {},
        "mdns_services": []
    }
    assert classify_device(dev_cam) == "IP Camera"

    # Scenario B: Smartphone connected without camera running
    dev_phone = {
        "open_ports": [],
        "banners": {},
        "vendor": "Randomized / Private MAC (Mobile Device)",
        "model": "Xiaomi-12S-Pro",
        "upnp_meta": {},
        "mdns_services": []
    }
    assert classify_device(dev_phone) == "Smartphone / Mobile Device"

def test_ghost_arp_device_suppression():
    """Verify that a stale ARP lease with 0 ports, 0 mDNS, 0 UPnP, and dead connection is NOT cataloged."""
    engine = SecurityScannerEngine()
    
    # Check that liveness returns False for an inactive / stale ARP IP
    is_alive = engine.check_host_alive("192.168.137.99", open_ports=[], mac="C2:BB:10:E0:91:E2")
    assert is_alive is False

def test_form_login_false_positive_prevention():
    """Verify that a login form returning 200 OK with 'Login Failed' is NOT falsely accepted."""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import threading
    import time
    from app.audit.credential_checker import test_http_auth

    class FailedFormHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><form action='/login'><input type='password' name='password'></form></body></html>")

        def do_POST(self):
            # Returns 200 OK with login failure and re-renders form
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Login failed. Incorrect username or password.<input type='password' name='password'></body></html>")

        def log_message(self, format, *args):
            return

    srv = HTTPServer(("127.0.0.1", 18889), FailedFormHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)

    try:
        res = test_http_auth("127.0.0.1", 18889, [("admin", "admin"), ("root", "root")])
        assert res["matched_credential"] is None
        assert res["is_open_access"] is False
    finally:
        srv.shutdown()
        srv.server_close()

def test_non_sensitive_api_not_flagged_as_open_access():
    """Verify that benign status APIs (e.g. IoT Gateway on port 5000) are not flagged as open access violations."""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import threading
    import time
    from app.audit.credential_checker import test_http_auth

    class SafeApiHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"system": "IoT Core Gateway", "status": "OPERATIONAL", "devices": []}')

        def log_message(self, format, *args):
            return

    srv = HTTPServer(("127.0.0.1", 18890), SafeApiHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)

    try:
        res = test_http_auth("127.0.0.1", 18890, [("admin", "admin")])
        assert res["is_open_access"] is False
        assert res["matched_credential"] is None
    finally:
        srv.shutdown()
        srv.server_close()

def test_banner_grabber_supports_alt_ports():
    """Verify that banner grabber handles ports 8089, 8443, 8888."""
    from app.discovery.banner_grabber import inspect_all_banners
    banners = inspect_all_banners("127.0.0.1", [8089, 8443, 8888])
    assert "http_8089" in banners
    assert "http_8443" in banners
    assert "http_8888" in banners

def test_wan_subnet_and_ip_isolation():
    """Verify that upstream home/office Wi-Fi (192.168.1.x) is never recognized as an edge IoT IP."""
    assert is_edge_ip("192.168.1.1") is False
    assert is_edge_ip("192.168.1.21") is False
    assert is_edge_ip("192.168.1.100") is False
    assert is_edge_ip("192.168.137.155") is True
    assert is_edge_ip("172.28.10.5") is True
    assert is_edge_ip("172.28.99.100") is True

    primary = get_primary_edge_cidr()
    assert not primary.startswith("192.168.1.")

def test_edge_only_arp_filtering(monkeypatch):
    """Verify that get_arp_hosts(edge_only=True) filters out foreign WAN entries."""
    engine = SecurityScannerEngine()
    fake_arp_output = """
Interface: 192.168.1.21 --- 0xa
  Internet Address      Physical Address      Type
  192.168.1.1           c4-2c-7b-0d-47-08     dynamic
  192.168.1.13          a8-a1-59-ec-4e-52     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static

Interface: 192.168.137.1 --- 0xc
  Internet Address      Physical Address      Type
  192.168.137.155       82-f9-da-8b-0a-90     static
"""
    import subprocess
    monkeypatch.setattr(subprocess, "check_output", lambda *args, **kwargs: fake_arp_output)

    # When edge_only=True (default), home router 192.168.1.1 must NOT appear
    edge_hosts = engine.get_arp_hosts(edge_only=True)
    assert "192.168.1.1" not in edge_hosts
    assert "192.168.1.13" not in edge_hosts
    assert "192.168.137.155" in edge_hosts
    assert edge_hosts["192.168.137.155"] == "82:F9:DA:8B:0A:90"

def test_presence_check_purges_wan_and_marks_disconnected_hotspot_offline(monkeypatch):
    """Verify presence check removes leaked WAN devices and immediately marks disconnected hotspot phone as OFFLINE."""
    engine = SecurityScannerEngine()

    # Pre-populate inventory with:
    # 1. Foreign WAN router that leaked in previously
    # 2. Smartphone connected on Windows Mobile Hotspot
    engine.inventory = {
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "mac": "C4:2C:7B:0D:47:08",
            "device_type": "IoT Gateway / Router",
            "is_online": True,
            "risk_level": "LOW",
            "open_ports": [80]
        },
        "192.168.137.155": {
            "ip": "192.168.137.155",
            "mac": "82:F9:DA:8B:0A:90",
            "device_type": "Smartphone / Mobile Device",
            "is_online": True,
            "risk_level": "LOW",
            "open_ports": []
        }
    }

    # Simulate phone disconnected: hotspot API returns empty list, and ping / port check fails
    import app.scanner_engine as se
    monkeypatch.setattr(se, "get_hotspot_active_clients", lambda force_refresh=False: [])
    monkeypatch.setattr(engine, "check_host_alive", lambda ip, **kwargs: False)
    monkeypatch.setattr(engine, "get_arp_hosts", lambda edge_only=True: {})

    engine.presence_check_cycle()

    # 1. Foreign WAN IP must be purged
    assert "192.168.1.1" not in engine.inventory

    # 2. Hotspot phone must be immediately marked OFFLINE
    assert "192.168.137.155" in engine.inventory
    assert engine.inventory["192.168.137.155"]["is_online"] is False

    # 3. Alert must be recorded
    offline_alerts = [a for a in engine.alerts if "Offline" in a["title"] or a["device_ip"] == "192.168.137.155"]
    assert len(offline_alerts) >= 1

    # 4. Summary statistics must accurately report 0 online devices
    stats = engine.get_summary_statistics()
    assert stats["total_devices"] == 1
    assert stats["online_devices"] == 0
    assert stats["offline_devices"] == 1

def test_execute_network_scan_marks_dead_devices_offline(monkeypatch):
    """Verify that running a scan on a CIDR marks non-responsive inventory devices as OFFLINE."""
    engine = SecurityScannerEngine()
    engine.inventory = {
        "192.168.137.155": {
            "ip": "192.168.137.155",
            "mac": "82:F9:DA:8B:0A:90",
            "device_type": "Smartphone / Mobile Device",
            "is_online": True,
            "risk_level": "LOW",
            "open_ports": []
        }
    }

    import app.scanner_engine as se
    monkeypatch.setattr(se, "get_hotspot_active_clients", lambda force_refresh=False: [])
    monkeypatch.setattr(engine, "check_host_alive", lambda ip, **kwargs: False)
    monkeypatch.setattr(engine, "get_arp_hosts", lambda edge_only=True: {})
    monkeypatch.setattr(se, "discover_mdns_devices", lambda timeout: [])
    monkeypatch.setattr(se, "discover_upnp_devices", lambda timeout: [])

    asyncio.run(engine.execute_network_scan("192.168.137.0/24", timeout_discovery=0.1))

    assert engine.inventory["192.168.137.155"]["is_online"] is False

