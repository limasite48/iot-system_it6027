"""
Unit Tests for Scope Management & Authorization Service (net-sec)
"""

import pytest
from app.scoping.scope_service import ScopeManager, GLOBAL_SCOPE_MANAGER

def test_authorized_hotspot_scope_allowed():
    res = GLOBAL_SCOPE_MANAGER.check_scope("192.168.137.0/24")
    assert res["allowed"] is True
    assert "Hotspot" in res["vlan_name"]
    assert res["vlan_id"] == 100

def test_authorized_virtual_iot_scope_allowed():
    res = GLOBAL_SCOPE_MANAGER.check_scope("172.28.10.0/24")
    assert res["allowed"] is True
    assert res["vlan_id"] == 10

def test_single_ip_subnet_in_authorized_scope():
    res = GLOBAL_SCOPE_MANAGER.check_scope("192.168.137.50/32")
    assert res["allowed"] is True

def test_public_wan_strictly_rejected():
    res = GLOBAL_SCOPE_MANAGER.check_scope("8.8.8.0/24")
    assert res["allowed"] is False
    assert "Public Internet" in res["reason"]

def test_upstream_home_lan_rejected():
    res = GLOBAL_SCOPE_MANAGER.check_scope("192.168.1.0/24")
    assert res["allowed"] is False
    assert "Scope Violation" in res["reason"]

def test_loopback_rejected():
    res = GLOBAL_SCOPE_MANAGER.check_scope("127.0.0.0/8")
    assert res["allowed"] is False

def test_dynamic_scope_addition():
    mgr = ScopeManager()
    assert mgr.check_scope("10.0.50.0/24")["allowed"] is False
    mgr.add_scope("10.0.50.0/24", "Lab Test Subnet", vlan_id=50)
    assert mgr.check_scope("10.0.50.0/24")["allowed"] is True
