"""
Firmware & CVE Matching Engine (net-sec)
Matches discovered device banners, UPnP descriptors, and vendor/model strings
against the curated IoT CVE database using CPE 2.3 normalization and semantic version evaluation.
"""

import os
import json
from typing import List, Dict, Any, Optional

from app.audit.cpe_normalizer import CpeNormalizer, compare_versions

CVE_DB_PATH = os.path.join(os.path.dirname(__file__), "cve_database.json")

def load_cve_database() -> List[Dict[str, Any]]:
    try:
        with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Warning loading CVE database: {e}")
        return []

def match_cves_for_device(device_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Correlate device metadata against the CVE database.
    Integrates CPE 2.3 normalization with semantic version evaluation,
    backed by fallback banner and vendor/product co-occurrence matching.
    """
    database = load_cve_database()
    matched_cves = []
    
    # 1. Standardize device metadata into candidate CPE 2.3 URIs
    cpe_candidates = CpeNormalizer.extract_cpe_candidates(device_info)

    # 2. Build text corpus for fallback keyword matching
    search_corpus = []
    if device_info.get("vendor"):
        search_corpus.append(str(device_info["vendor"]).lower())
    if device_info.get("model"):
        search_corpus.append(str(device_info["model"]).lower())

    upnp_meta = device_info.get("upnp_meta", {})
    for k, v in upnp_meta.items():
        if v:
            search_corpus.append(str(v).lower())

    banners = device_info.get("banners", {})
    for port_key, b_info in banners.items():
        if isinstance(b_info, dict):
            for k in ["server", "auth_realm", "title", "powered_by"]:
                val = b_info.get(k)
                if val:
                    search_corpus.append(str(val).lower())
        elif isinstance(b_info, str):
            search_corpus.append(b_info.lower())

    combined_text = " ".join(search_corpus)

    for entry in database:
        is_matched = False
        matched_cpe_uri = entry.get("cpe_uri", "")

        # A. CPE 2.3 & Semantic Version Matching
        target_cpe_list = entry.get("target_cpe_list", [entry.get("cpe_uri", "")])
        for cand in cpe_candidates:
            cand_cpe = cand.get("cpe_uri", "")
            for crit_cpe in target_cpe_list:
                if crit_cpe and CpeNormalizer.match_cpe_criteria(cand_cpe, crit_cpe):
                    # Check semantic version constraints
                    ver = cand.get("version", "*")
                    if ver and ver != "*":
                        in_range = compare_versions(
                            ver,
                            version_start_including=entry.get("version_start_including"),
                            version_end_including=entry.get("version_end_including"),
                            version_end_excluding=entry.get("version_end_excluding")
                        )
                        if in_range:
                            is_matched = True
                            matched_cpe_uri = cand_cpe
                            break
                    else:
                        is_matched = True
                        matched_cpe_uri = cand_cpe
                        break
            if is_matched:
                break

        # B. Fallback 1: Direct Banner pattern matching
        if not is_matched:
            for banner_pattern in entry.get("affected_banners", []):
                if banner_pattern.lower() in combined_text:
                    is_matched = True
                    break

        # C. Fallback 2: Product and Vendor co-occurrence matching
        if not is_matched:
            vendor_match = any(v.lower() in combined_text for v in entry.get("affected_vendors", []))
            product_match = any(p.lower() in combined_text for p in entry.get("affected_products", []))
            if vendor_match and product_match:
                is_matched = True

        # D. Special case: Anonymous MQTT check
        if entry["cve_id"] == "CVE-2023-38836":
            mqtt_banner = banners.get("mqtt_1883", {})
            if isinstance(mqtt_banner, dict) and mqtt_banner.get("anonymous_allowed"):
                is_matched = True

        if is_matched:
            # Deduplicate by CVE ID
            if not any(c["cve_id"] == entry["cve_id"] for c in matched_cves):
                matched_cves.append({
                    "cve_id": entry["cve_id"],
                    "title": entry["title"],
                    "cpe": matched_cpe_uri,
                    "cvss_score": entry["cvss_score"],
                    "severity": entry["severity"],
                    "description": entry["description"],
                    "remediation": entry["remediation"]
                })

    # Sort matched CVEs by CVSS score descending
    matched_cves.sort(key=lambda x: x["cvss_score"], reverse=True)
    return matched_cves

if __name__ == "__main__":
    test_device = {
        "vendor": "D-Link Systems",
        "model": "DCS-932L",
        "banners": {
            "http_8080": {
                "server": "GoAhead-Webs/2.5",
                "auth_realm": 'Basic realm="D-Link DCS-932L"'
            }
        }
    }
    print("[*] Matching CVEs for test device:")
    cves = match_cves_for_device(test_device)
    for c in cves:
        print(f"  [+] {c['cve_id']} ({c['severity']} {c['cvss_score']}): {c['title']} [CPE: {c.get('cpe')}]")
