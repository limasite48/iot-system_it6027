"""
Network Environment & Adapter Discovery Engine (net-sec)
Dynamically identifies local network adapters, edge IoT subnets (Hotspot, Wi-Fi, Ethernet),
gateway addresses, authoritative Windows Mobile Hotspot connected clients, and reverse DNS hostnames.
Eliminates hardcoded IP/subnet assumptions across the platform.
"""

import os
import json
import socket
import platform
import subprocess
import ipaddress
import psutil
from typing import List, Dict, Any, Optional, Set

HOTSPOT_PS_SCRIPT = os.path.join(os.path.dirname(__file__), "get_hotspot_clients.ps1")

def get_host_ips() -> Set[str]:
    """Retrieve all local IPv4 addresses assigned to host network interfaces."""
    host_ips = {"127.0.0.1", "localhost"}
    try:
        for _, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET:
                    host_ips.add(a.address)
    except Exception:
        pass
    return host_ips

def detect_active_subnets() -> List[Dict[str, Any]]:
    """
    Detect all active non-loopback IPv4 subnets across network interfaces.
    Identifies whether each interface is a Windows Mobile Hotspot adapter,
    Wi-Fi interface, or standard Ethernet connection.
    """
    subnets = []
    stats = psutil.net_if_stats()
    
    for iface_name, addrs in psutil.net_if_addrs().items():
        iface_stat = stats.get(iface_name)
        is_up = iface_stat.isup if iface_stat else True
        if not is_up:
            continue

        for a in addrs:
            if a.family != socket.AF_INET:
                continue
            ip = a.address
            netmask = a.netmask or "255.255.255.0"
            
            # Skip loopback and APIPA / link-local addresses
            if ip.startswith("127.") or ip.startswith("169.254."):
                continue
            
            try:
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                is_hotspot = (
                    "Local Area Connection" in iface_name or
                    "Hotspot" in iface_name.lower() or
                    ip.startswith("192.168.137.") or
                    ip.startswith("192.168.173.")
                )
                is_docker_iot = (
                    ip.startswith("172.28.10.") or
                    ip.startswith("172.28.99.")
                )
                is_edge = is_hotspot or is_docker_iot

                subnets.append({
                    "interface": iface_name,
                    "ip": ip,
                    "netmask": netmask,
                    "cidr": str(network),
                    "network_address": str(network.network_address),
                    "num_addresses": network.num_addresses,
                    "is_hotspot": is_hotspot,
                    "is_edge": is_edge,
                    "is_wan": not is_edge,
                    "is_up": is_up
                })
            except Exception:
                continue

    return subnets

def get_primary_edge_cidr() -> str:
    """
    Determine the primary CIDR to audit.
    Prioritizes active Windows Mobile Hotspot subnet, then Docker mock subnets.
    Always defaults to the designated Edge Subnet (192.168.137.0/24).
    NEVER returns the upstream home/office WAN interface.
    """
    subnets = detect_active_subnets()
    # 1. Hotspot subnet
    for s in subnets:
        if s.get("is_hotspot"):
            return s["cidr"]

    # 2. Virtual Docker IoT subnet
    for s in subnets:
        if s.get("is_edge"):
            return s["cidr"]

    # Always default to standard Edge Subnet (Windows Mobile Hotspot)
    return "192.168.137.0/24"

def is_edge_ip(ip_str: str) -> bool:
    """Check if an IP belongs to an IoT Edge subnet rather than upstream WAN."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        edge_cidrs = ["192.168.137.0/24", "192.168.173.0/24", "172.28.10.0/24", "172.28.99.0/24"]
        for s in detect_active_subnets():
            if s.get("is_edge"):
                edge_cidrs.append(s["cidr"])
        return any(ip_obj in ipaddress.ip_network(c, strict=False) for c in edge_cidrs)
    except Exception:
        return False

import threading
_HOTSPOT_CLIENTS_CACHE: List[Dict[str, str]] = []
_HOTSPOT_CACHE_TIME: float = 0.0
_HOTSPOT_LOCK = threading.Lock()

def get_hotspot_active_clients(force_refresh: bool = False) -> List[Dict[str, str]]:
    """
    Query Windows Mobile Hotspot Tethering API via PowerShell with 2.0s TTL caching.
    Prevents spawning redundant PowerShell processes when auditing multiple hosts.
    """
    global _HOTSPOT_CLIENTS_CACHE, _HOTSPOT_CACHE_TIME
    import time
    now = time.time()
    with _HOTSPOT_LOCK:
        if not force_refresh and (now - _HOTSPOT_CACHE_TIME < 2.0):
            return list(_HOTSPOT_CLIENTS_CACHE)

    if platform.system() != "Windows" or not os.path.exists(HOTSPOT_PS_SCRIPT):
        return []

    try:
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", HOTSPOT_PS_SCRIPT]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout.strip())
            clients = []
            for c in data.get("Clients", []):
                mac = c.get("MacAddress", "").replace("-", ":").upper()
                hostname = c.get("Hostname", "")
                clients.append({"mac": mac, "hostname": hostname})
            with _HOTSPOT_LOCK:
                _HOTSPOT_CLIENTS_CACHE = clients
                _HOTSPOT_CACHE_TIME = time.time()
            return clients
    except Exception:
        pass
    return []

def resolve_reverse_hostname(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Perform quick reverse DNS lookup for device hostname."""
    try:
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            # Strip local suffixes
            for suffix in [".mshome.net", ".local", ".lan", ".home"]:
                if name.lower().endswith(suffix):
                    name = name[:-len(suffix)]
            return name
        finally:
            socket.setdefaulttimeout(orig_timeout)
    except Exception:
        return None
