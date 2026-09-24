"""
VLAN Scoping & Isolation Policy Engine (net-sec bonus requirement)
Groups devices by network scopes / VLANs and calculates quarantine isolation actions.
"""

import ipaddress
from typing import List, Dict, Any

SUBNET_VLAN_MAP = {
    "192.168.137.0/24": {"vlan_id": 100, "name": "VLAN 100 - Physical Edge WLAN (Hotspot)"},
    "172.28.10.0/24":   {"vlan_id": 10,  "name": "VLAN 10 - Standard IoT Operational Subnet"},
    "172.28.99.0/24":   {"vlan_id": 99,  "name": "VLAN 99 - IoT Quarantine & Isolation Subnet"},
    "192.168.1.0/24":   {"vlan_id": 1,   "name": "VLAN 1 - Primary Office/Home LAN"}
}

def resolve_vlan_for_ip(ip_str: str) -> Dict[str, Any]:
    """Map an IP address to its corresponding VLAN scope."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for cidr, vlan_info in SUBNET_VLAN_MAP.items():
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return vlan_info
        # Default fallback
        network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
        return {"vlan_id": 999, "name": f"VLAN Custom - Subnet {network.network_address}/24"}
    except Exception:
        return {"vlan_id": 0, "name": "VLAN Unknown"}

def evaluate_scoping_policy(device: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate device risk and determine VLAN isolation / quarantine actions.
    """
    has_default_pw = device.get("default_credentials_found", False)
    is_open_access = device.get("is_open_access", False)
    cves = device.get("cves", [])
    max_cvss = max([c.get("cvss_score", 0.0) for c in cves], default=0.0)

    # Determine Risk Level
    if has_default_pw or is_open_access or max_cvss >= 9.0:
        risk_level = "CRITICAL"
    elif max_cvss >= 7.0:
        risk_level = "HIGH"
    elif max_cvss >= 4.0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Isolation Decision
    if risk_level in ["CRITICAL", "HIGH"] or has_default_pw or is_open_access:
        if is_open_access:
            msg = "VIOLATION: Unauthenticated open access detected (No password required). Video stream / controls completely unshielded."
        elif has_default_pw:
            msg = "VIOLATION: Publicly known default credentials accepted. Immediate network isolation required."
        else:
            msg = f"VIOLATION: High-severity CVEs identified (Max CVSS {max_cvss}). Quarantine isolation mandated."

        quarantine_action = {
            "risk_level": risk_level,
            "max_cvss": max_cvss,
            "quarantine_required": True,
            "recommended_vlan": "VLAN 99 (Quarantine)",
            "policy_violation": True,
            "policy_message": msg,
            "remediation": "Move switch port / assign 802.1Q tag for VLAN 99. Enforce strong authentication and disable open streams."
        }
    else:
        quarantine_action = {
            "risk_level": risk_level,
            "max_cvss": max_cvss,
            "quarantine_required": False,
            "recommended_vlan": "VLAN 10 (Operational)",
            "policy_violation": False,
            "policy_message": "COMPLIANT: No critical CVEs, default passwords, or open interfaces detected.",
            "remediation": "Maintain current security posture and periodic firmware auditing."
        }

    return quarantine_action

def group_devices_by_vlan(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Group inventory devices by their VLAN scope and compute aggregate statistics."""
    vlan_groups = {}
    for d in devices:
        vlan_info = d.get("vlan", {})
        vlan_name = vlan_info.get("name", "Unassigned")
        if vlan_name not in vlan_groups:
            vlan_groups[vlan_name] = {
                "vlan_id": vlan_info.get("vlan_id", 0),
                "vlan_name": vlan_name,
                "device_count": 0,
                "critical_count": 0,
                "quarantine_count": 0,
                "devices": []
            }
        group = vlan_groups[vlan_name]
        group["device_count"] += 1
        if d.get("risk_level") in ["CRITICAL", "HIGH"]:
            group["critical_count"] += 1
        if d.get("scoping_policy", {}).get("quarantine_required"):
            group["quarantine_count"] += 1
        group["devices"].append({
            "ip": d.get("ip"),
            "mac": d.get("mac"),
            "device_type": d.get("device_type"),
            "vendor": d.get("vendor"),
            "risk_level": d.get("risk_level")
        })

    return vlan_groups
