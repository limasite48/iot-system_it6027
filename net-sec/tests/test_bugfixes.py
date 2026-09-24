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
    get_hotspot_active_clients
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
