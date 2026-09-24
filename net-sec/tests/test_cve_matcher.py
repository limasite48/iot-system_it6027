import pytest
from app.audit.cve_matcher import match_cves_for_device, load_cve_database

def test_cve_database_loaded():
    db = load_cve_database()
    assert len(db) >= 5
    cve_ids = [entry["cve_id"] for entry in db]
    assert "CVE-2020-25078" in cve_ids
    assert "CVE-2017-8225" in cve_ids
    assert "CVE-2019-14923" in cve_ids

def test_camera_cve_matching():
    # Simulates D-Link DCS-932L camera with GoAhead-Webs/2.5 banner
    device = {
        "vendor": "D-Link Systems",
        "model": "DCS-932L",
        "banners": {
            "http_8080": {
                "server": "GoAhead-Webs/2.5",
                "auth_realm": 'Basic realm="D-Link DCS-932L"'
            }
        }
    }
    matched = match_cves_for_device(device)
    assert len(matched) >= 1
    assert any(c["cve_id"] == "CVE-2020-25078" for c in matched)
    top_cve = matched[0]
    assert top_cve["severity"] == "CRITICAL"
    assert top_cve["cvss_score"] == 9.8

def test_smartplug_cve_matching():
    # Simulates TP-Link HS100 smart plug
    device = {
        "vendor": "TP-Link",
        "model": "HS100",
        "banners": {
            "http_9999": {
                "server": "TP-LINK Smart Plug HTTP Server 1.0"
            }
        }
    }
    matched = match_cves_for_device(device)
    assert any(c["cve_id"] == "CVE-2019-14923" for c in matched)

def test_clean_device_no_false_positives():
    # Simulates a modern hardened device
    device = {
        "vendor": "Apple, Inc.",
        "model": "iPhone 15",
        "banners": {
            "https_443": {
                "server": "Apache/2.4.58",
                "auth_realm": ""
            }
        }
    }
    matched = match_cves_for_device(device)
    assert len(matched) == 0
