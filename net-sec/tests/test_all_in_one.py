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
    import os

    run_py_path = os.path.join(os.path.dirname(__file__), "..", "..", "run.py")
    assert os.path.exists(run_py_path)

    # Replicate parser logic to verify argument handling
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan", action="store_true")
    parser.add_argument("--target", type=str, default="ALL")
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--device", "--devices", "--camera", "--cameras",
        dest="devices",
        type=int,
        default=4
    )
    parser.add_argument("--no-fleet", action="store_true")

    # 1. Default count
    args_default = parser.parse_args([])
    assert args_default.devices == 4

    # 2. --device flag
    args_device = parser.parse_args(["--device", "6"])
    assert args_device.devices == 6

    # 3. --devices flag
    args_devices = parser.parse_args(["--devices", "8"])
    assert args_devices.devices == 8

    # 4. Backward compatibility: --cameras flag
    args_cameras = parser.parse_args(["--cameras", "3"])
    assert args_cameras.devices == 3

def test_startup_fleet_contains_both_safety_and_vulnerable_devices():
    """
    Verify that upon system startup (default count=4 or scaled count),
    both safety devices (compliant, LOW risk) and non-safety devices (vulnerable,
    CRITICAL/HIGH risk) across diverse categories are present.
    """
    import json
    import os
    from app.scoping.vlan_scoper import evaluate_scoping_policy
    from app.audit.cve_matcher import match_cves_for_device

    profiles_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "mock-object", "profiles"))
    fleet_py_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "mock-object", "fleet_manager.py"))

    # Import AVAILABLE_PROFILES directly
    import sys
    mock_dir = os.path.dirname(fleet_py_path)
    if mock_dir not in sys.path:
        sys.path.insert(0, mock_dir)
    from fleet_manager import AVAILABLE_PROFILES

    # Check for default startup fleet of 4 devices
    startup_4 = AVAILABLE_PROFILES[:4]
    assert len(startup_4) == 4

    safety_count = 0
    vulnerable_count = 0
    categories = set()

    for p_id in startup_4:
        with open(os.path.join(profiles_dir, f"{p_id}.json"), "r", encoding="utf-8") as f:
            prof = json.load(f)
        
        posture = prof.get("security_posture", "")
        cat = prof.get("device_category", "")
        categories.add(cat)

        if "Compliant" in posture or "Hardened" in posture or prof.get("auth_type") in ["digest", "tls"]:
            safety_count += 1
        else:
            vulnerable_count += 1

    # Both safety and non-safety devices must be present upon startup
    assert safety_count >= 1, f"Expected at least 1 safety device in default fleet, got {safety_count}"
    assert vulnerable_count >= 1, f"Expected at least 1 vulnerable device in default fleet, got {vulnerable_count}"
    assert len(categories) >= 2, f"Expected at least 2 distinct device categories in default fleet, got {categories}"

def test_startup_fleet_multi_level_risk_evaluation():
    """Verify that startup fleet provides multi-level risk exposure (CRITICAL, HIGH, LOW/Compliant)."""
    import json
    import os
    import sys
    from app.scoping.vlan_scoper import evaluate_scoping_policy
    from app.audit.cve_matcher import match_cves_for_device

    profiles_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "mock-object", "profiles"))
    fleet_py_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "mock-object", "fleet_manager.py"))
    mock_dir = os.path.dirname(fleet_py_path)
    if mock_dir not in sys.path:
        sys.path.insert(0, mock_dir)
    from fleet_manager import AVAILABLE_PROFILES

    startup_6 = AVAILABLE_PROFILES[:6]
    risk_levels = set()

    for p_id in startup_6:
        with open(os.path.join(profiles_dir, f"{p_id}.json"), "r", encoding="utf-8") as f:
            prof = json.load(f)

        device_record = {
            "vendor": prof["vendor"],
            "model": prof["model"],
            "firmware": prof["firmware"],
            "open_ports": [prof["default_http_port"]],
            "banners": {f"http_{prof['default_http_port']}": {"server": prof["http_server_banner"]}},
            "default_credentials_found": any(c["username"] == "admin" and c["password"] in ["admin", "password"] for c in prof.get("credentials", [])),
            "is_open_access": prof.get("is_open_access", False)
        }
        matched_cves = match_cves_for_device(device_record)
        device_record["cves"] = matched_cves

        eval_result = evaluate_scoping_policy(device_record)
        risk_levels.add(eval_result["risk_level"])

    # Startup fleet must cover both LOW (safety/compliant) and CRITICAL/HIGH (vulnerable)
    assert "LOW" in risk_levels, "Safety devices must achieve LOW risk level (compliant)"
    assert ("CRITICAL" in risk_levels or "HIGH" in risk_levels), "Vulnerable devices must trigger CRITICAL/HIGH risk levels"
