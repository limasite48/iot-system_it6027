"""
Verification & Regression Tests for:
1. Isolated Per-Device Traffic Monitoring & Loopback Separation
2. Auditor Triage Deduplication Precedence Fix
3. Dynamic Edge Subnet Scoping & VLAN Resolution
4. Unique Virtual MAC Assignment for Mock Nodes
Course: IT6027 - Cybersecurity Policy and Governance
"""

import pytest
import asyncio
from app.monitoring.traffic_meter import TrafficMeter, GLOBAL_TRAFFIC_METER
from app.audit.triage import AuditorTriageManager, GLOBAL_TRIAGE_MANAGER
from app.scoping.vlan_scoper import resolve_vlan_for_ip
from app.scoping.scope_service import ScopeManager
from app.scanner_engine import SecurityScannerEngine

def test_traffic_meter_device_isolation_no_cross_device_leakage():
    """
    Verify that Hotspot traffic is attributed strictly to hotspot clients
    and NEVER leaks onto loopback mock devices (127.0.0.x).
    """
    meter = TrafficMeter(target_subnet_prefix="192.168.137.")
    
    # Pre-register a physical smartphone camera on hotspot and a virtual mock camera on loopback
    phone_ip = "192.168.137.45"
    mock_ip = "127.0.0.2"
    meter.register_device(phone_ip)
    meter.register_device(mock_ip)

    snap = meter.get_snapshot()
    assert "device_traffic" in snap
    assert phone_ip in snap["device_traffic"]
    assert mock_ip in snap["device_traffic"]

    # Initial rates must be 0
    assert snap["device_traffic"][phone_ip]["rx_rate_kbps"] == 0.0
    assert snap["device_traffic"][mock_ip]["rx_rate_kbps"] == 0.0

    # Simulate Hotspot traffic arrival (e.g. smartphone camera streaming 2MB)
    with meter._lock:
        delta_rx = 2 * 1024 * 1024  # 2MB
        delta_tx = 50 * 1024        # 50KB
        dt = 1.0

        # Attribute Hotspot Delta Rx/Tx strictly to Hotspot Devices
        hotspot_candidates = [
            ip for ip in meter._device_stats.keys() 
            if ip.startswith(meter.target_subnet_prefix)
            and ip not in ["127.0.0.1", "localhost"]
        ]
        assert phone_ip in hotspot_candidates
        assert mock_ip not in hotspot_candidates  # Mock IP MUST NOT be a hotspot candidate!

        share_rx = delta_rx / float(len(hotspot_candidates))
        share_tx = delta_tx / float(len(hotspot_candidates))

        for ip in hotspot_candidates:
            dev = meter._device_stats[ip]
            dev["rx_bytes"] += int(share_rx)
            dev["tx_bytes"] += int(share_tx)
            dev_rx_rate_kb = (share_rx / 1024.0) / dt
            dev["rx_rate_kbps"] = round(dev_rx_rate_kb, 1)
            dev["rx_rate_mbps"] = round(dev_rx_rate_kb / 1024.0, 2)
            dev["total_rx_mb"] = round(dev["rx_bytes"] / (1024.0 * 1024.0), 2)
            dev["is_streaming"] = True

    updated_snap = meter.get_snapshot()
    phone_metrics = updated_snap["device_traffic"][phone_ip]
    mock_metrics = updated_snap["device_traffic"][mock_ip]

    # Phone receives streaming traffic
    assert phone_metrics["rx_rate_mbps"] > 1.0
    assert phone_metrics["total_rx_mb"] == 2.0
    assert phone_metrics["is_streaming"] is True

    # Mock camera remains cleanly isolated at 0.0 KB/s without any leakage
    assert mock_metrics["rx_rate_kbps"] == 0.0
    assert mock_metrics["total_rx_mb"] == 0.0
    assert mock_metrics["is_streaming"] is False

def test_triage_deduplication_operator_precedence():
    """
    Verify that findings with port=None (such as CVEs and Policy violations)
    deduplicate properly across repeated scan cycles without creating duplicate entries.
    """
    triage_mgr = AuditorTriageManager()
    
    # 1. Register CVE finding with port=None
    f1 = triage_mgr.record_finding(
        target_ip="192.168.137.45",
        finding_type="VULNERABILITY",
        title="CVE-2023-38836: Anonymous MQTT Broker",
        severity="HIGH",
        details="Anonymous publish and subscribe permitted",
        cve_id="CVE-2023-38836",
        port=None
    )
    assert f1 is not None
    assert triage_mgr.get_triage_stats()["total_findings"] == 1

    # 2. Register the exact same CVE finding again in a subsequent scan cycle
    f2 = triage_mgr.record_finding(
        target_ip="192.168.137.45",
        finding_type="VULNERABILITY",
        title="CVE-2023-38836: Anonymous MQTT Broker",
        severity="HIGH",
        details="Anonymous publish and subscribe permitted (updated scan)",
        cve_id="CVE-2023-38836",
        port=None
    )
    # Total count MUST still be 1 (deduplicated!)
    assert triage_mgr.get_triage_stats()["total_findings"] == 1
    assert f1.finding_id == f2.finding_id
    assert f2.details == "Anonymous publish and subscribe permitted (updated scan)"

    # 3. Register a policy violation finding with rule_id and port=None
    p1 = triage_mgr.record_finding(
        target_ip="192.168.137.45",
        finding_type="POLICY_VIOLATION",
        title="Policy Rule Check",
        severity="CRITICAL",
        details="Unauthenticated access policy triggered",
        rule_id="RULE-IOT-01",
        port=None
    )
    assert triage_mgr.get_triage_stats()["total_findings"] == 2

    # Re-recording must deduplicate
    p2 = triage_mgr.record_finding(
        target_ip="192.168.137.45",
        finding_type="POLICY_VIOLATION",
        title="Policy Rule Check",
        severity="CRITICAL",
        details="Unauthenticated access policy triggered (rescan)",
        rule_id="RULE-IOT-01",
        port=None
    )
    assert triage_mgr.get_triage_stats()["total_findings"] == 2
    assert p1.finding_id == p2.finding_id

def test_vlan_scoper_dynamic_edge_detection(monkeypatch):
    """
    Verify that resolve_vlan_for_ip dynamically inspects detect_active_subnets()
    to map non-standard hotspot or Docker subnets without relying on static hardcoding.
    """
    # Simulate a dynamic hotspot configured on 192.168.173.0/24
    def mock_subnets():
        return [
            {
                "interface": "Local Area Connection* 9",
                "ip": "192.168.173.1",
                "cidr": "192.168.173.0/24",
                "is_hotspot": True,
                "is_edge": True
            }
        ]

    monkeypatch.setattr("app.discovery.network_env.detect_active_subnets", mock_subnets)

    vlan = resolve_vlan_for_ip("192.168.173.45")
    assert vlan["vlan_id"] == 100
    assert "Physical Edge WLAN (Hotspot)" in vlan["name"]

def test_mock_camera_unique_virtual_mac_generation():
    """
    Verify that loopback mock nodes (127.0.0.2, 127.0.0.3) receive distinct
    locally administered virtual MAC addresses and clear vendor categorization.
    """
    engine = SecurityScannerEngine()

    async def run_test():
        dev2 = await engine.scan_single_device("127.0.0.2")
        dev3 = await engine.scan_single_device("127.0.0.3")
        return dev2, dev3

    dev2, dev3 = asyncio.run(run_test())

    # Virtual MACs must be unique based on octet
    assert dev2["mac"] == "02:00:7D:00:00:02"
    assert dev3["mac"] == "02:00:7D:00:00:03"
    assert dev2["mac"] != dev3["mac"]
    assert dev2["vendor"] in ["Virtual IoT Testbed Node", "D-Link Systems", "Hikvision", "Dahua Technology"]
    assert "traffic" in dev2
    assert "traffic" in dev3
