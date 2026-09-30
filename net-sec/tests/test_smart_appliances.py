"""
Automated Test Suite: Smart Appliance Diversity, Security Postures & CVE Feeds
Course: IT6027 - Cybersecurity Policy and Governance

Validates:
1. Multi-feed CVE Manager loading smart appliance vulnerability feeds.
2. Device classification for Smart TVs, Air Conditioners, Fans, and Thermostats.
3. Precedence over generic smartphone brand fallbacks (Samsung TV and Xiaomi Fan).
4. Accurate CVE matching on vulnerable profiles.
5. Strict false-positive prevention on hardened/secure profiles.
6. Open-access sensitivity detection for appliance control interfaces.
7. Profile integrity across all 15 mock fleet configurations.
"""

import os
import json
import pytest

from app.audit.cve_manager import GLOBAL_CVE_MANAGER
from app.audit.cve_matcher import match_cves_for_device
from app.audit.credential_checker import is_sensitive_iot_service
from app.scoping.classifier import classify_device
from app.scoping.vlan_scoper import evaluate_scoping_policy

PROFILES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "mock-object", "profiles"))

def load_mock_profile(profile_id: str) -> dict:
    file_path = os.path.join(PROFILES_DIR, f"{profile_id}.json")
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

# -----------------------------------------------------------------------------
# 1. Multi-Feed CVE Manager Verification
# -----------------------------------------------------------------------------
def test_smart_appliances_cve_feed_loaded():
    """Verify smart appliances CVE feed is loaded and contains 8 expected CVEs."""
    cves = GLOBAL_CVE_MANAGER.get_all_cves()
    cve_ids = {c["cve_id"] for c in cves}

    expected_appliance_cves = [
        "CVE-2019-12297",  # Samsung Tizen TV
        "CVE-2023-6317",   # LG webOS TV Auth Bypass
        "CVE-2023-6318",   # LG webOS TV Command Injection
        "CVE-2021-38144",  # Daikin Air Conditioner
        "CVE-2020-28001",  # Gree AC UDP Hijack
        "CVE-2018-11315",  # Radio Thermostat CT50
        "CVE-2021-31560",  # Xiaomi Smart Fan
        "CVE-2022-26132"   # Tuya Smart SDK
    ]

    for expected_cve in expected_appliance_cves:
        assert expected_cve in cve_ids, f"Expected {expected_cve} in CVE database"

    assert len(cves) >= 19, f"Total CVE count should be at least 19, got {len(cves)}"

# -----------------------------------------------------------------------------
# 2. Classifier Category Tests & Smartphone Precedence Tests
# -----------------------------------------------------------------------------
def test_classification_smart_tv():
    """Smart TVs must be categorized as 'Smart TV / Media Player' (not Smartphone)."""
    # Samsung TV
    samsung_tv = {
        "vendor": "Samsung Electronics",
        "model": "UN55RU7100 Tizen Smart TV",
        "open_ports": [8001],
        "banners": {"http_8001": {"server": "Samsung-Tizen-TV/1.0", "title": "Samsung Tizen 4K Smart TV"}}
    }
    assert classify_device(samsung_tv) == "Smart TV / Media Player"

    # LG webOS TV
    lg_tv = {
        "vendor": "LG Electronics",
        "model": "OLED55C9 webOS TV",
        "open_ports": [3000],
        "banners": {"http_3000": {"server": "LG-webOS/4.2", "title": "LG webOS TV"}}
    }
    assert classify_device(lg_tv) == "Smart TV / Media Player"

    # Hardened Sony TV
    sony_tv = {
        "vendor": "Sony Corporation",
        "model": "BRAVIA 4K Smart TV",
        "open_ports": [8443],
        "banners": {"http_8443": {"server": "Sony-Bravia-TV/11.0", "title": "Sony BRAVIA 4K Smart TV"}}
    }
    assert classify_device(sony_tv) == "Smart TV / Media Player"

def test_classification_smart_ac():
    """Air conditioners must be categorized as 'Smart Air Conditioner / HVAC'."""
    daikin_ac = {
        "vendor": "Daikin Industries",
        "model": "BRP069A41 Inverter AC",
        "open_ports": [80],
        "banners": {"http_80": {"server": "Daikin-HTTP-Server/1.2", "title": "Daikin Inverter Smart Air Conditioner"}}
    }
    assert classify_device(daikin_ac) == "Smart Air Conditioner / HVAC"

    gree_ac = {
        "vendor": "Gree Electric Appliances",
        "model": "Smart Inverter Air Conditioner",
        "open_ports": [8443],
        "banners": {"http_8443": {"title": "Gree Smart Air Conditioner Control"}}
    }
    assert classify_device(gree_ac) == "Smart Air Conditioner / HVAC"

def test_classification_smart_fan():
    """Smart Fans must be categorized as 'Smart Fan / Air Purifier' (not Smartphone)."""
    xiaomi_fan = {
        "vendor": "Xiaomi Communications",
        "model": "Mi Smart Standing Fan 2",
        "open_ports": [8080],
        "banners": {"http_8080": {"title": "Xiaomi Mi Smart Standing Fan"}}
    }
    assert classify_device(xiaomi_fan) == "Smart Fan / Air Purifier"

    dyson_fan = {
        "vendor": "Dyson",
        "model": "Dyson Pure Cool Link TP04",
        "open_ports": [8443],
        "banners": {"http_8443": {"title": "Dyson Pure Cool Purifying Fan"}}
    }
    assert classify_device(dyson_fan) == "Smart Fan / Air Purifier"

def test_classification_smart_thermostat():
    """Smart Thermostats must be categorized as 'Smart Thermostat'."""
    radio_tstat = {
        "vendor": "Radio Thermostat",
        "model": "CT50 7-Day Programmable",
        "open_ports": [80],
        "banners": {"http_80": {"title": "Radio Thermostat CT50"}}
    }
    assert classify_device(radio_tstat) == "Smart Thermostat"

    nest_tstat = {
        "vendor": "Google Nest",
        "model": "Nest Learning Thermostat 3rd Gen",
        "open_ports": [8443],
        "banners": {"http_8443": {"title": "Google Nest Learning Thermostat"}}
    }
    assert classify_device(nest_tstat) == "Smart Thermostat"

# -----------------------------------------------------------------------------
# 3. Vulnerability Matching on Diverse Appliance Endpoints
# -----------------------------------------------------------------------------
def test_vulnerable_samsung_tv_cve_matching():
    profile = load_mock_profile("samsung_tizen_tv")
    device = {
        "vendor": profile["vendor"],
        "model": profile["model"],
        "firmware": profile["firmware"],
        "open_ports": [profile["default_http_port"]],
        "banners": {f"http_{profile['default_http_port']}": {"server": profile["http_server_banner"]}}
    }
    matched = match_cves_for_device(device)
    cve_ids = [c["cve_id"] for c in matched]
    assert "CVE-2019-12297" in cve_ids

def test_vulnerable_lg_tv_cve_matching():
    profile = load_mock_profile("lg_webos_tv")
    device = {
        "vendor": profile["vendor"],
        "model": profile["model"],
        "firmware": profile["firmware"],
        "open_ports": [profile["default_http_port"]],
        "banners": {f"http_{profile['default_http_port']}": {"server": profile["http_server_banner"]}}
    }
    matched = match_cves_for_device(device)
    cve_ids = [c["cve_id"] for c in matched]
    assert "CVE-2023-6317" in cve_ids
    assert "CVE-2023-6318" in cve_ids

def test_vulnerable_daikin_ac_cve_matching():
    profile = load_mock_profile("daikin_smart_ac")
    device = {
        "vendor": profile["vendor"],
        "model": profile["model"],
        "firmware": profile["firmware"],
        "open_ports": [profile["default_http_port"]],
        "banners": {f"http_{profile['default_http_port']}": {"server": profile["http_server_banner"]}}
    }
    matched = match_cves_for_device(device)
    cve_ids = [c["cve_id"] for c in matched]
    assert "CVE-2021-38144" in cve_ids

def test_vulnerable_radio_thermostat_cve_matching():
    profile = load_mock_profile("radio_thermostat_ct50")
    device = {
        "vendor": profile["vendor"],
        "model": profile["model"],
        "firmware": profile["firmware"],
        "open_ports": [profile["default_http_port"]],
        "banners": {f"http_{profile['default_http_port']}": {"server": profile["http_server_banner"]}}
    }
    matched = match_cves_for_device(device)
    cve_ids = [c["cve_id"] for c in matched]
    assert "CVE-2018-11315" in cve_ids

def test_vulnerable_xiaomi_fan_cve_matching():
    profile = load_mock_profile("xiaomi_smart_fan")
    device = {
        "vendor": profile["vendor"],
        "model": profile["model"],
        "firmware": profile["firmware"],
        "open_ports": [profile["default_http_port"]],
        "banners": {f"http_{profile['default_http_port']}": {"server": profile["http_server_banner"]}}
    }
    matched = match_cves_for_device(device)
    cve_ids = [c["cve_id"] for c in matched]
    assert "CVE-2021-31560" in cve_ids

# -----------------------------------------------------------------------------
# 4. Secure & Compliant Appliances (Strict False-Positive Verification)
# -----------------------------------------------------------------------------
def test_secure_sony_tv_posture():
    profile = load_mock_profile("hardened_sony_tv")
    device = {
        "vendor": profile["vendor"],
        "model": profile["model"],
        "firmware": profile["firmware"],
        "open_ports": [profile["default_http_port"]],
        "banners": {f"http_{profile['default_http_port']}": {"server": profile["http_server_banner"]}}
    }
    matched = match_cves_for_device(device)
    assert len(matched) == 0, f"Hardened Sony TV should have 0 CVEs matched, got: {matched}"

    eval_result = evaluate_scoping_policy({
        "default_credentials_found": False,
        "is_open_access": False,
        "cves": matched
    })
    assert eval_result["risk_level"] == "LOW"
    assert eval_result["quarantine_required"] is False
    assert eval_result["recommended_vlan"] == "VLAN 10 (Operational)"

def test_secure_gree_ac_posture():
    """Gree AC with patched firmware 3.5.2 must NOT match CVE-2020-28001 (<= 2.1.0)."""
    profile = load_mock_profile("hardened_gree_ac")
    device = {
        "vendor": profile["vendor"],
        "model": profile["model"],
        "firmware": profile["firmware"],
        "open_ports": [profile["default_http_port"]],
        "banners": {f"http_{profile['default_http_port']}": {"server": profile["http_server_banner"]}}
    }
    matched = match_cves_for_device(device)
    assert len(matched) == 0, f"Patched Gree AC should have 0 CVEs matched, got: {matched}"

    eval_result = evaluate_scoping_policy({
        "default_credentials_found": False,
        "is_open_access": False,
        "cves": matched
    })
    assert eval_result["risk_level"] == "LOW"
    assert eval_result["quarantine_required"] is False

def test_secure_dyson_fan_posture():
    profile = load_mock_profile("dyson_pure_cool")
    device = {
        "vendor": profile["vendor"],
        "model": profile["model"],
        "firmware": profile["firmware"],
        "open_ports": [profile["default_http_port"]],
        "banners": {f"http_{profile['default_http_port']}": {"server": profile["http_server_banner"]}}
    }
    matched = match_cves_for_device(device)
    assert len(matched) == 0

    eval_result = evaluate_scoping_policy({
        "default_credentials_found": False,
        "is_open_access": False,
        "cves": matched
    })
    assert eval_result["risk_level"] == "LOW"
    assert eval_result["quarantine_required"] is False

def test_secure_nest_thermostat_posture():
    profile = load_mock_profile("nest_smart_thermostat")
    device = {
        "vendor": profile["vendor"],
        "model": profile["model"],
        "firmware": profile["firmware"],
        "open_ports": [profile["default_http_port"]],
        "banners": {f"http_{profile['default_http_port']}": {"server": profile["http_server_banner"]}}
    }
    matched = match_cves_for_device(device)
    assert len(matched) == 0

    eval_result = evaluate_scoping_policy({
        "default_credentials_found": False,
        "is_open_access": False,
        "cves": matched
    })
    assert eval_result["risk_level"] == "LOW"
    assert eval_result["quarantine_required"] is False

# -----------------------------------------------------------------------------
# 5. Open-Access Sensitivity Detection on IoT Appliance Endpoints
# -----------------------------------------------------------------------------
def test_open_access_sensitivity_detection():
    """Verify is_sensitive_iot_service flags unauthenticated appliance endpoints."""
    # Daikin AC control info
    daikin_resp = "ret=OK,pow=1,mode=3,adv=,stemp=24.0,shum=0\n"
    assert is_sensitive_iot_service(80, daikin_resp, "text/plain") is True

    # Radio Thermostat CT50 status
    tstat_resp = '{"temp": 72.5, "tmode": 1, "fmode": 0, "override": 0, "hold": 0, "model": "CT50"}'
    assert is_sensitive_iot_service(80, tstat_resp, "application/json") is True

    # Samsung Tizen TV info
    tv_resp = '<html><head><title>Samsung Tizen Smart TV</title></head><body>Media Receiver Online: /api/v2/</body></html>'
    assert is_sensitive_iot_service(8001, tv_resp, "text/html") is True

    # Xiaomi Fan status
    fan_resp = '{"power": "on", "speed": 3, "oscillating": true, "mode": "natural"}'
    assert is_sensitive_iot_service(8080, fan_resp, "application/json") is True

    # Benign web server - should NOT be flagged as sensitive IoT service
    benign_resp = '<html><head><title>Welcome to Nginx</title></head><body><h1>Hello World</h1></body></html>'
    assert is_sensitive_iot_service(80, benign_resp, "text/html") is False

# -----------------------------------------------------------------------------
# 6. Profile Integrity Verification across all 15 Mock Profiles
# -----------------------------------------------------------------------------
def test_all_15_mock_profiles_validity():
    """Verify all 15 mock profiles in mock-object/profiles/ are valid JSON and well-formed."""
    expected_profiles = [
        # Cameras (6)
        "dlink_dcs932l", "hikvision_ds2cd", "dahua_ipc",
        "open_access_cam", "ip_webcam", "hardened_cam",
        # Smart TVs (3)
        "samsung_tizen_tv", "lg_webos_tv", "hardened_sony_tv",
        # Smart ACs (2)
        "daikin_smart_ac", "hardened_gree_ac",
        # Smart Fans (2)
        "xiaomi_smart_fan", "dyson_pure_cool",
        # Smart Thermostats (2)
        "radio_thermostat_ct50", "nest_smart_thermostat"
    ]

    for p_id in expected_profiles:
        profile = load_mock_profile(p_id)
        assert profile.get("profile_id") == p_id
        assert "name" in profile
        assert "vendor" in profile
        assert "model" in profile
        assert "device_category" in profile
        assert "security_posture" in profile
        assert "default_http_port" in profile
