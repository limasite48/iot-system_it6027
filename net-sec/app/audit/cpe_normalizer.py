"""
IoT CPE 2.3 Normalizer & Semantic Version Evaluator (net-sec)
Converts discovered IoT hardware, firmware, and embedded software banners
into standardized NIST Common Platform Enumeration (CPE 2.3) identifiers
and performs semantic version constraint evaluation.
"""

import re
from typing import Dict, Any, List, Optional, Tuple

# Common IoT embedded software, firmware, and hardware vendor mappings
VENDOR_MAP = {
    "d-link": "dlink",
    "d-link systems": "dlink",
    "d-link corporation": "dlink",
    "tp-link": "tp-link",
    "tp-link corporation": "tp-link",
    "xiongmai": "xiongmai",
    "hangzhou xiongmai": "xiongmai",
    "sofia": "xiongmai",
    "hikvision": "hikvision",
    "hikvision digital technology": "hikvision",
    "dahua": "dahua",
    "zhejiang dahua technology": "dahua",
    "realtek": "realtek",
    "embedthis": "embedthis",
    "eclipse": "eclipse",
    "mosquitto": "eclipse",
    "tbk": "tbk"
}

PRODUCT_MAP = {
    "goahead-webs": "goahead",
    "goahead_webs": "goahead",
    "app-webs": "app-webs"
}

APPLICATION_NAMES = {
    "goahead", "goahead-webs", "uc-httpd", "miniigd", "mosquitto",
    "busybox", "lighttpd", "boa", "app-webs", "sofia"
}

def clean_identifier(val: str) -> str:
    """Normalize string for CPE component (lowercase, alphanumeric, underscores/hyphens)."""
    if not val:
        return "*"
    val = val.strip().lower()
    val = re.sub(r"[\s/]+", "_", val)
    val = re.sub(r"[^a-z0-9_\-\.]", "", val)
    return val or "*"

def parse_semver(ver_str: str) -> Tuple[Any, ...]:
    """
    Parse version string into a comparable tuple of integers and strings.
    E.g. '1.14.04' -> (1, 14, 4), '2.5.0' -> (2, 5, 0), '1.0-beta' -> (1, 0, 'beta')
    """
    if not ver_str or ver_str in ["*", "-"]:
        return ()
    cleaned = re.sub(r"^v", "", ver_str.strip().lower())
    parts = re.split(r"[\.\-_]", cleaned)
    parsed = []
    for p in parts:
        if p.isdigit():
            parsed.append(int(p))
        elif p:
            # Handle mixed numbers like '14b'
            subparts = re.findall(r"\d+|\D+", p)
            for sp in subparts:
                parsed.append(int(sp) if sp.isdigit() else sp)
    return tuple(parsed)

def compare_versions(target_ver: str, 
                     version_start_including: Optional[str] = None,
                     version_end_including: Optional[str] = None,
                     version_end_excluding: Optional[str] = None) -> bool:
    """
    Evaluate whether target_ver satisfies semantic version constraints.
    Returns True if target_ver is within the specified range.
    """
    if not target_ver or target_ver in ["*", "-"]:
        return True
    
    t_parsed = parse_semver(target_ver)
    if not t_parsed:
        return True

    # Pad tuples for equal length comparison
    def pad(t1: tuple, t2: tuple) -> Tuple[tuple, tuple]:
        max_len = max(len(t1), len(t2))
        p1 = list(t1) + [0] * (max_len - len(t1))
        p2 = list(t2) + [0] * (max_len - len(t2))
        return tuple(p1), tuple(p2)

    if version_start_including:
        s_parsed = parse_semver(version_start_including)
        t_pad, s_pad = pad(t_parsed, s_parsed)
        if t_pad < s_pad:
            return False

    if version_end_including:
        e_parsed = parse_semver(version_end_including)
        t_pad, e_pad = pad(t_parsed, e_parsed)
        if t_pad > e_pad:
            return False

    if version_end_excluding:
        ex_parsed = parse_semver(version_end_excluding)
        t_pad, ex_pad = pad(t_parsed, ex_parsed)
        if t_pad >= ex_pad:
            return False

    return True

class CpeNormalizer:
    """Standardizes IoT hardware, firmware, and embedded software into NIST CPE 2.3."""

    @staticmethod
    def build_cpe_uri(part: str, vendor: str, product: str, version: str = "*", 
                       update: str = "*", edition: str = "*") -> str:
        """
        Build CPE 2.3 formatted string:
        cpe:2.3:[part]:[vendor]:[product]:[version]:[update]:[edition]:*:*:*:*:*
        part: 'a' (application), 'o' (operating system / firmware), 'h' (hardware)
        """
        p_clean = part if part in ["a", "o", "h"] else "h"
        v_clean = clean_identifier(VENDOR_MAP.get(vendor.lower().strip(), vendor))
        p_raw = clean_identifier(product)
        prod_clean = PRODUCT_MAP.get(p_raw, p_raw)
        ver_clean = clean_identifier(version) if version and version != "*" else "*"
        return f"cpe:2.3:{p_clean}:{v_clean}:{prod_clean}:{ver_clean}:{update}:{edition}:*:*:*:*:*"

    @staticmethod
    def extract_cpe_candidates(device_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze device banners, UPnP metadata, and attributes to synthesize
        standardized CPE candidates with part and version breakdown.
        """
        candidates = []
        vendor = device_info.get("vendor", "")
        model = device_info.get("model", "")
        banners = device_info.get("banners", {})
        upnp_meta = device_info.get("upnp_meta", {})

        # 1. Hardware / Device level CPE
        if vendor and vendor != "Unknown" and model and model != "Unspecified":
            hw_cpe = CpeNormalizer.build_cpe_uri("h", vendor, model)
            candidates.append({
                "cpe_uri": hw_cpe,
                "part": "h",
                "vendor": clean_identifier(VENDOR_MAP.get(vendor.lower(), vendor)),
                "product": clean_identifier(model),
                "version": "*",
                "source": "device_identity"
            })

        # 2. Firmware version from UPnP metadata
        if upnp_meta:
            mfr = upnp_meta.get("manufacturer") or vendor
            mod = upnp_meta.get("model_name") or model
            mod_num = upnp_meta.get("model_number") or ""
            # Check for version in model_number or description
            ver_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", mod_num)
            ver = ver_match.group(1) if ver_match else "*"
            if mfr and mod:
                fw_cpe = CpeNormalizer.build_cpe_uri("o", mfr, f"{mod}_firmware", ver)
                candidates.append({
                    "cpe_uri": fw_cpe,
                    "part": "o",
                    "vendor": clean_identifier(VENDOR_MAP.get(mfr.lower(), mfr)),
                    "product": clean_identifier(f"{mod}_firmware"),
                    "version": ver,
                    "source": "upnp_metadata"
                })

        # 3. Embedded Application / Web Server Banners
        for port_key, b_info in banners.items():
            server_str = ""
            if isinstance(b_info, dict):
                server_str = b_info.get("server", "")
            elif isinstance(b_info, str):
                server_str = b_info

            if server_str:
                # E.g. "GoAhead-Webs/2.5.0", "uc-httpd 1.0.0", "lighttpd/1.4.35", "Mosquitto/2.0.18"
                match = re.search(r"([a-zA-Z0-9_\-]+)[/\s]+([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9]+)?)", server_str)
                if match:
                    app_name, app_ver = match.group(1), match.group(2)
                    app_vendor = "embedthis" if "goahead" in app_name.lower() else (
                        "eclipse" if "mosquitto" in app_name.lower() else (
                            "xiongmai" if "uc-httpd" in app_name.lower() else vendor or "unknown"
                        )
                    )
                    app_cpe = CpeNormalizer.build_cpe_uri("a", app_vendor, app_name, app_ver)
                    candidates.append({
                        "cpe_uri": app_cpe,
                        "part": "a",
                        "vendor": clean_identifier(VENDOR_MAP.get(app_vendor.lower(), app_vendor)),
                        "product": clean_identifier(app_name),
                        "version": app_ver,
                        "source": f"banner_{port_key}"
                    })

            # Check RTSP server banners
            if isinstance(b_info, dict) and "rtsp" in port_key:
                rtsp_server = b_info.get("server", "")
                if "sofia" in rtsp_server.lower():
                    candidates.append({
                        "cpe_uri": CpeNormalizer.build_cpe_uri("a", "xiongmai", "sofia_rtsp", "*"),
                        "part": "a",
                        "vendor": "xiongmai",
                        "product": "sofia_rtsp",
                        "version": "*",
                        "source": "rtsp_banner"
                    })

            # Check MQTT banners
            if "mqtt" in port_key:
                candidates.append({
                    "cpe_uri": CpeNormalizer.build_cpe_uri("a", "eclipse", "mosquitto", "*"),
                    "part": "a",
                    "vendor": "eclipse",
                    "product": "mosquitto",
                    "version": "*",
                    "source": "mqtt_banner"
                })

        return candidates

    @staticmethod
    def match_cpe_criteria(target_cpe: str, criteria_cpe: str) -> bool:
        """
        Determine if target_cpe matches criteria_cpe considering wildcards.
        Criteria CPE format: cpe:2.3:part:vendor:product:version:...
        """
        t_parts = target_cpe.split(":")
        c_parts = criteria_cpe.split(":")
        if len(t_parts) < 5 or len(c_parts) < 5:
            return False

        # Match part (a, o, h)
        if c_parts[2] != "*" and t_parts[2] != "*" and c_parts[2] != t_parts[2]:
            return False

        # Match vendor
        if c_parts[3] != "*" and t_parts[3] != "*" and c_parts[3] != t_parts[3]:
            return False

        # Match product
        if c_parts[4] != "*" and t_parts[4] != "*" and c_parts[4] not in t_parts[4] and t_parts[4] not in c_parts[4]:
            return False

        return True
