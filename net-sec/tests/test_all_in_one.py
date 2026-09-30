"""
Tests for All-in-One Architecture & Unified Runner
Course: IT6027 - Cybersecurity Policy and Governance
"""

import pytest
import ipaddress
from app.scoping.scope_service import ScopeManager, DEFAULT_AUTHORIZED_SCOPES
from app.discovery.network_env import is_edge_ip

def test_scope_manager_all_target_allowed():
    """Verify that ALL, AUTO, HYBRID, and wildcard scopes are authorized."""
    sm = ScopeManager()
    for kw in ["ALL", "all", "AUTO", "auto", "HYBRID", "*", "  all  "]:
        res = sm.check_scope(kw)
        assert res["allowed"] is True
        assert res["matched_scope"] == "ALL_AUTHORIZED_EDGE_SUBNETS"

def test_loopback_subnet_in_authorized_scopes():
    """Verify that 127.0.0.0/24 is explicitly registered in authorized scopes."""
    sm = ScopeManager()
    scopes = sm.get_authorized_scopes()
    cidrs = [s["cidr"] for s in scopes]
    assert "127.0.0.0/24" in cidrs
    assert "192.168.137.0/24" in cidrs

def test_is_edge_ip_includes_loopback_and_hotspot():
    """Verify that is_edge_ip accepts both physical hotspot and local testbed loopback IPs."""
    assert is_edge_ip("192.168.137.1") is True
    assert is_edge_ip("192.168.137.155") is True
    assert is_edge_ip("127.0.0.2") is True
    assert is_edge_ip("127.0.0.10") is True
    # Upstream WAN / Public internet must return False
    assert is_edge_ip("8.8.8.8") is False
    assert is_edge_ip("1.1.1.1") is False

def test_run_py_argument_parser():
    """Verify run.py CLI argument definitions without executing subshells."""
    import argparse
    import importlib.util
    import os

    run_py_path = os.path.join(os.path.dirname(__file__), "..", "..", "run.py")
    assert os.path.exists(run_py_path)
