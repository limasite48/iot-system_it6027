"""
Scope Management & Authorization Service (net-sec)
Enforces strict network boundary verification (ref_1.md Module G1).
Guarantees that all active scanning and deep audits are restricted strictly
to authorized IoT edge subnets (Hotspot WLAN, Virtual IoT VLANs) and forbids
unauthorized probing of external WANs, loopbacks, or enterprise LANs.
"""

import ipaddress
from datetime import datetime
from typing import Dict, Any, List, Optional

DEFAULT_AUTHORIZED_SCOPES = [
    {
        "cidr": "192.168.137.0/24",
        "name": "Physical Edge Hotspot WLAN (VLAN 100)",
        "vlan_id": 100,
        "description": "Windows SoftAP edge Wi-Fi for smartphones and physical IoT cameras."
    },
    {
        "cidr": "172.28.10.0/24",
        "name": "Standard Operational IoT Subnet (VLAN 10)",
        "vlan_id": 10,
        "description": "Virtual operational IoT subnet for smart plugs, cameras, and sensors."
    },
    {
        "cidr": "172.28.99.0/24",
        "name": "IoT Isolation & Quarantine Subnet (VLAN 99)",
        "vlan_id": 99,
        "description": "Restricted quarantine subnet for insecure or compromised devices."
    }
]

class ScopeManager:
    def __init__(self, authorized_scopes: Optional[List[Dict[str, Any]]] = None):
        self._scopes: List[Dict[str, Any]] = list(authorized_scopes or DEFAULT_AUTHORIZED_SCOPES)
        self._audit_log: List[Dict[str, Any]] = []

    def get_authorized_scopes(self) -> List[Dict[str, Any]]:
        """Return list of authorized CIDR boundaries."""
        return list(self._scopes)

    def add_scope(self, cidr: str, name: str, vlan_id: int = 0, description: str = ""):
        """Dynamically add an authorized audit range."""
        network = ipaddress.ip_network(cidr, strict=False)
        self._scopes.append({
            "cidr": str(network),
            "name": name,
            "vlan_id": vlan_id,
            "description": description
        })

    def check_scope(self, target_cidr: str) -> Dict[str, Any]:
        """
        Verify whether a target CIDR or IP is permitted for active scanning.
        Enforces strict compliance with authorization policies.
        """
        now = datetime.now().isoformat()
        try:
            target_net = ipaddress.ip_network(target_cidr, strict=False)
        except Exception as e:
            res = {
                "allowed": False,
                "cidr": target_cidr,
                "reason": f"Invalid CIDR notation: {e}",
                "timestamp": now
            }
            self._audit_log.append(res)
            return res

        # Reject public internet (WAN) and loopback
        if target_net.is_global:
            res = {
                "allowed": False,
                "cidr": str(target_net),
                "reason": "Scope Violation: Public Internet (WAN) ranges are strictly forbidden.",
                "timestamp": now
            }
            self._audit_log.append(res)
            return res

        if target_net.is_loopback:
            res = {
                "allowed": False,
                "cidr": str(target_net),
                "reason": "Scope Violation: Loopback scanning is not authorized as an edge network.",
                "timestamp": now
            }
            self._audit_log.append(res)
            return res

        # Check against authorized scopes
        for auth in self._scopes:
            auth_net = ipaddress.ip_network(auth["cidr"], strict=False)
            # Allow if target_net is equal to or a sub-network of the authorized network
            if target_net.subnet_of(auth_net):
                res = {
                    "allowed": True,
                    "cidr": str(target_net),
                    "matched_scope": auth["cidr"],
                    "vlan_name": auth["name"],
                    "vlan_id": auth.get("vlan_id", 0),
                    "reason": f"Authorized by policy for {auth['name']}.",
                    "timestamp": now
                }
                self._audit_log.append(res)
                return res

        # Target is outside declared scopes (e.g. 192.168.1.0/24 upstream home network)
        res = {
            "allowed": False,
            "cidr": str(target_net),
            "reason": "Scope Violation: Target is not in the authorized edge IoT subnet registry.",
            "timestamp": now
        }
        self._audit_log.append(res)
        return res

    def is_ip_in_scope(self, ip_str: str) -> bool:
        """Fast check for single IP."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback or ip_obj.is_global or ip_obj.is_multicast:
                return False
            for auth in self._scopes:
                auth_net = ipaddress.ip_network(auth["cidr"], strict=False)
                if ip_obj in auth_net:
                    return True
        except Exception:
            pass
        return False

GLOBAL_SCOPE_MANAGER = ScopeManager()
