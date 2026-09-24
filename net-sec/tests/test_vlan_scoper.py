import pytest
from app.scoping.vlan_scoper import resolve_vlan_for_ip, evaluate_scoping_policy, group_devices_by_vlan

def test_resolve_vlan_hotspot():
    vlan = resolve_vlan_for_ip("192.168.137.5")
    assert vlan["vlan_id"] == 100
    assert "Hotspot" in vlan["name"]

def test_resolve_vlan_simulated():
    vlan = resolve_vlan_for_ip("172.28.10.20")
    assert vlan["vlan_id"] == 10
    assert "Standard IoT" in vlan["name"]

def test_quarantine_policy_triggered_on_default_password():
    device = {
        "default_credentials_found": True,
        "cves": []
    }
    policy = evaluate_scoping_policy(device)
    assert policy["quarantine_required"] is True
    assert policy["risk_level"] == "CRITICAL"
    assert "Quarantine" in policy["recommended_vlan"]

def test_quarantine_policy_triggered_on_critical_cve():
    device = {
        "default_credentials_found": False,
        "cves": [{"cvss_score": 9.8}]
    }
    policy = evaluate_scoping_policy(device)
    assert policy["quarantine_required"] is True
    assert policy["risk_level"] == "CRITICAL"

def test_compliant_device_scoping():
    device = {
        "default_credentials_found": False,
        "cves": []
    }
    policy = evaluate_scoping_policy(device)
    assert policy["quarantine_required"] is False
    assert policy["risk_level"] == "LOW"
    assert "Operational" in policy["recommended_vlan"]
