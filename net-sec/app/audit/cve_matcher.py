"""
Firmware & CVE Matching Engine (net-sec)
Matches discovered device banners, UPnP descriptors, and vendor/model strings
against the scalable IoT CVE multi-feed database using CPE 2.3 normalization
and semantic version evaluation.
"""

from typing import List, Dict, Any, Optional
from app.audit.cpe_normalizer import CpeNormalizer, compare_versions
from app.audit.cve_manager import GLOBAL_CVE_MANAGER

def load_cve_database() -> List[Dict[str, Any]]:
    """Legacy compatibility accessor: fetches all CVEs from the multi-feed manager."""
    return GLOBAL_CVE_MANAGER.get_all_cves()

def match_cves_for_device(device_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Correlate device metadata against the CVE multi-feed database.
    Integrates tripartite CPE 2.3 normalization with semantic version evaluation,
    backed by fallback banner and vendor/product co-occurrence matching.
    """
    database = GLOBAL_CVE_MANAGER.get_all_cves()
    matched_cves = []
    
    # 1. Standardize device metadata into candidate CPE 2.3 URIs (h, o, a)
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

        version_out_of_bounds = False
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
                            version_out_of_bounds = True
                    else:
                        is_matched = True
                        matched_cpe_uri = cand_cpe
                        break
            if is_matched:
                break

        # B. Fallback 1: Direct Banner pattern matching (only if version not confirmed out-of-bounds)
        if not is_matched and not version_out_of_bounds:
            for banner_pattern in entry.get("affected_banners", []):
                if banner_pattern.lower() in combined_text:
                    is_matched = True
                    break

        # C. Fallback 2: Product and Vendor co-occurrence matching (only if version not confirmed out-of-bounds)
        if not is_matched and not version_out_of_bounds:
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
                    "cpe": matched_cpe_uri or entry.get("cpe_uri", ""),
                    "cvss_score": entry["cvss_score"],
                    "cvss_v3": entry.get("cvss_v3", {}),
                    "severity": entry["severity"],
                    "description": entry["description"],
                    "remediation": entry["remediation"],
                    "required_open_ports": entry.get("required_open_ports", []),
                    "required_service": entry.get("required_service", ""),
                    "cisa_kev": entry.get("cisa_kev", False),
                    "known_botnet_vector": entry.get("known_botnet_vector", []),
                    "cwe_id": entry.get("cwe_id", "")
                })

    # Sort matched CVEs by CVSS score descending
    matched_cves.sort(key=lambda x: x["cvss_score"], reverse=True)
    return matched_cves
