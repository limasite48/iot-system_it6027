"""
Unit Tests for IoT CPE 2.3 Normalizer & Semantic Version Evaluator (net-sec)
Verifies CPE 2.3 standardization and version-range matching across at least 5
distinct IoT vendor/product/version pairs.
"""

import pytest
from app.audit.cpe_normalizer import (
    CpeNormalizer,
    compare_versions,
    parse_semver,
    clean_identifier
)
from app.audit.cve_matcher import match_cves_for_device

def test_cpe_builder_syntax():
    """Verify built CPE 2.3 conforms to the NIST 13-component specification."""
    cpe = CpeNormalizer.build_cpe_uri("o", "D-Link Systems", "DCS-932L_firmware", "1.14.04")
    assert cpe.startswith("cpe:2.3:o:dlink:dcs-932l_firmware:1.14.04:")
    parts = cpe.split(":")
    assert len(parts) >= 12
    assert parts[2] == "o"
    assert parts[3] == "dlink"

def test_semver_parsing_and_comparison():
    """Verify semantic version parsing and range boundaries."""
    assert parse_semver("1.14.04") == (1, 14, 4)
    assert parse_semver("2.5.0") == (2, 5, 0)
    
    # End including
    assert compare_versions("1.14.04", version_end_including="1.14.04") is True
    assert compare_versions("1.14.03", version_end_including="1.14.04") is True
    assert compare_versions("1.14.05", version_end_including="1.14.04") is False

    # End excluding
    assert compare_versions("1.0.0", version_end_excluding="1.0.1") is True
    assert compare_versions("1.0.1", version_end_excluding="1.0.1") is False

    # Start including
    assert compare_versions("2.5.0", version_start_including="2.0.0", version_end_including="2.5.0") is True
    assert compare_versions("1.9.9", version_start_including="2.0.0") is False

def test_cpe_pair_1_dlink_camera():
    """Pair 1: D-Link DCS-932L with GoAhead-Webs 2.5 server banner."""
    device = {
        "vendor": "D-Link",
        "model": "DCS-932L",
        "banners": {
            "http_8080": {"server": "GoAhead-Webs/2.5.0"}
        },
        "upnp_meta": {
            "manufacturer": "D-Link",
            "model_name": "DCS-932L",
            "model_number": "1.14.04"
        }
    }
    candidates = CpeNormalizer.extract_cpe_candidates(device)
    cpe_uris = [c["cpe_uri"] for c in candidates]
    
    # Verify hardware, firmware, and application CPEs are generated
    assert any("cpe:2.3:h:dlink:dcs-932l" in uri for uri in cpe_uris)
    assert any("cpe:2.3:o:dlink:dcs-932l_firmware:1.14.04" in uri for uri in cpe_uris)
    assert any("cpe:2.3:a:embedthis:goahead:2.5.0" in uri for uri in cpe_uris)

    # Match CVE
    cves = match_cves_for_device(device)
    cve_ids = [c["cve_id"] for c in cves]
    assert "CVE-2020-25078" in cve_ids

def test_cpe_pair_2_xiongmai_dvr():
    """Pair 2: Xiongmai H.264 DVR with uc-httpd 1.0.0 banner."""
    device = {
        "vendor": "Xiongmai",
        "model": "H.264 DVR",
        "banners": {
            "http_80": {"server": "uc-httpd 1.0.0"}
        }
    }
    candidates = CpeNormalizer.extract_cpe_candidates(device)
    cpe_uris = [c["cpe_uri"] for c in candidates]
    assert any("cpe:2.3:a:xiongmai:uc-httpd:1.0.0" in uri for uri in cpe_uris)

    cves = match_cves_for_device(device)
    cve_ids = [c["cve_id"] for c in cves]
    assert "CVE-2017-8225" in cve_ids

def test_cpe_pair_3_tplink_smartplug():
    """Pair 3: TP-Link HS100 Smart Plug with XOR autokey banner."""
    device = {
        "vendor": "TP-Link",
        "model": "HS100",
        "banners": {
            "tcp_9999": "TP-LINK Smart Plug Protocol"
        }
    }
    candidates = CpeNormalizer.extract_cpe_candidates(device)
    cpe_uris = [c["cpe_uri"] for c in candidates]
    assert any("cpe:2.3:h:tp-link:hs100" in uri for uri in cpe_uris)

    cves = match_cves_for_device(device)
    cve_ids = [c["cve_id"] for c in cves]
    assert "CVE-2019-14923" in cve_ids

def test_cpe_pair_4_hikvision_camera():
    """Pair 4: Hikvision IP Camera with App-webs server banner."""
    device = {
        "vendor": "Hikvision",
        "model": "DS-2CD2032",
        "banners": {
            "http_80": {"server": "App-webs/5.5.0"}
        }
    }
    candidates = CpeNormalizer.extract_cpe_candidates(device)
    cpe_uris = [c["cpe_uri"] for c in candidates]
    assert any("hikvision" in uri for uri in cpe_uris)

    cves = match_cves_for_device(device)
    cve_ids = [c["cve_id"] for c in cves]
    assert "CVE-2021-36260" in cve_ids

def test_cpe_pair_5_realtek_miniigd_upnp():
    """Pair 5: Realtek miniigd UPnP daemon."""
    device = {
        "vendor": "Realtek",
        "model": "RTL8196C Router Gateway",
        "banners": {
            "http_52869": {"server": "miniigd/1.0 UPnP/1.0"}
        }
    }
    candidates = CpeNormalizer.extract_cpe_candidates(device)
    cpe_uris = [c["cpe_uri"] for c in candidates]
    assert any("miniigd:1.0" in uri for uri in cpe_uris)

    cves = match_cves_for_device(device)
    cve_ids = [c["cve_id"] for c in cves]
    assert "CVE-2014-8361" in cve_ids
