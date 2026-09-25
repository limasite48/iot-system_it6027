"""
Unified Security Scanner Engine (net-sec)
Orchestrates mDNS, UPnP, Port Scanning, Banner Grabbing, CVE Matching,
Default Credential Auditing, and VLAN Scoping.
Fully dynamic, eliminated hardcoded subnet assumptions and ghost ARP leases.
"""

import asyncio
import socket
import re
import subprocess
import platform
import ipaddress
from datetime import datetime
from typing import List, Dict, Any, Optional

from app.discovery.oui_resolver import resolve_mac_vendor
from app.discovery.mdns_listener import discover_mdns_devices
from app.discovery.upnp_scanner import discover_upnp_devices
from app.discovery.port_scanner import scan_host_ports
from app.discovery.banner_grabber import inspect_all_banners
from app.audit.cve_matcher import match_cves_for_device
from app.audit.credential_checker import test_device_credentials
from app.scoping.classifier import classify_device
from app.scoping.vlan_scoper import resolve_vlan_for_ip, evaluate_scoping_policy, group_devices_by_vlan
from app.monitoring.traffic_meter import GLOBAL_TRAFFIC_METER
from app.discovery.network_env import (
    detect_active_subnets,
    get_primary_edge_cidr,
    get_host_ips,
    get_hotspot_active_clients,
    resolve_reverse_hostname,
    is_edge_ip
)

class SecurityScannerEngine:
    def __init__(self):
        import threading
        self._lock = threading.RLock()
        self.inventory: Dict[str, Dict[str, Any]] = {}
        self.alerts: List[Dict[str, Any]] = []
        self.last_scan_time: Optional[str] = None
        self.is_scanning: bool = False
        self.presence_monitor_running: bool = False

    def get_arp_hosts(self, edge_only: bool = True) -> Dict[str, str]:
        """
        Read system ARP table to find known IPs and MAC addresses.
        When edge_only=True, suppresses upstream WAN/home Wi-Fi entries.
        """
        hosts = {}
        try:
            output = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
            pattern = re.compile(r"^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9a-fA-F-]+)\s+(\w+)", re.MULTILINE)
            for match in pattern.finditer(output):
                ip, mac, _ = match.groups()
                if not ip.endswith(".255") and not ip.startswith("224.") and not ip.startswith("239."):
                    if edge_only and not is_edge_ip(ip):
                        continue
                    hosts[ip] = mac.replace("-", ":").upper()
        except Exception:
            pass
        return hosts

    async def scan_single_device(self, ip: str, mac: str = "", mdns_info: List[Dict] = None, upnp_info: Dict = None) -> Dict[str, Any]:
        """Deep fingerprinting and vulnerability audit of a single host."""
        from app.discovery.port_scanner import COMMON_IOT_PORTS
        candidate_ports = set(COMMON_IOT_PORTS)
        if mdns_info:
            for s in mdns_info:
                if s.get("port"):
                    candidate_ports.add(s["port"])
        if upnp_info and upnp_info.get("port"):
            candidate_ports.add(upnp_info["port"])

        open_ports = await scan_host_ports(ip, ports=sorted(list(candidate_ports)))
        banners = await asyncio.to_thread(inspect_all_banners, ip, open_ports)
        vendor = resolve_mac_vendor(mac) if mac else "Unknown"

        # Extract UPnP metadata if available
        upnp_meta = upnp_info.get("xml_meta", {}) if upnp_info else {}
        model = upnp_meta.get("model_name", "")
        if not vendor or vendor == "Unknown":
            vendor = upnp_meta.get("manufacturer", "Unknown")

        # Resolve hostname via reverse DNS and Hotspot clients
        rev_hostname = resolve_reverse_hostname(ip)
        hotspot_clients = get_hotspot_active_clients()
        matched_client = next((c for c in hotspot_clients if c["mac"] == mac), None)
        if matched_client and matched_client.get("hostname"):
            rev_hostname = matched_client["hostname"]

        if rev_hostname and (not model or model == "Unspecified"):
            model = rev_hostname

        # Enrich vendor info for randomized mobile MACs
        if "Randomized / Private MAC" in vendor:
            name_check = f"{rev_hostname or ''} {model or ''}".lower()
            if "xiaomi" in name_check or "redmi" in name_check:
                vendor = "Xiaomi (Mobile Device - Private MAC)"
            elif "iphone" in name_check or "ipad" in name_check or "apple" in name_check:
                vendor = "Apple Inc. (Mobile Device - Private MAC)"
            elif "samsung" in name_check or "galaxy" in name_check:
                vendor = "Samsung (Mobile Device - Private MAC)"

        # Package raw device info
        raw_device = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "model": model,
            "open_ports": open_ports,
            "banners": banners,
            "upnp_meta": upnp_meta,
            "mdns_services": mdns_info or []
        }

        # 1. Device Type Classification (Mandatory)
        device_type = classify_device(raw_device)

        # 2. Firmware / CVE Matching (Mandatory)
        matched_cves = match_cves_for_device(raw_device)

        # 3. Default Password & Open Access Auditing (Mandatory)
        cred_audit = await asyncio.to_thread(test_device_credentials, ip, open_ports)
        is_open_access = any(f.get("is_open_access") for f in cred_audit.get("findings", []))
        default_creds_found = any(not f.get("is_open_access") for f in cred_audit.get("findings", []))

        # 4. VLAN Scoping & Quarantine Policy (Bonus)
        vlan = resolve_vlan_for_ip(ip)
        scoping_eval = evaluate_scoping_policy({
            "default_credentials_found": default_creds_found,
            "is_open_access": is_open_access,
            "cves": matched_cves
        })

        # Final aggregated device record
        full_record = {
            "ip": ip,
            "mac": mac or "Unknown",
            "vendor": vendor,
            "model": model or "Unspecified",
            "device_type": device_type,
            "open_ports": open_ports,
            "banners": banners,
            "upnp": upnp_info,
            "mdns": mdns_info or [],
            "cves": matched_cves,
            "default_credentials_found": default_creds_found,
            "is_open_access": is_open_access,
            "is_online": True,
            "missed_pings": 0,
            "credential_findings": cred_audit.get("findings", []),
            "vlan": vlan,
            "scoping_policy": scoping_eval,
            "risk_level": scoping_eval["risk_level"],
            "last_audited": datetime.now().isoformat()
        }

        # Generate Alerts if vulnerable (thread-safe)
        with self._lock:
            if default_creds_found or is_open_access:
                for finding in cred_audit.get("findings", []):
                    if finding.get("is_open_access"):
                        self.alerts.append({
                            "timestamp": datetime.now().isoformat(),
                            "severity": "CRITICAL",
                            "device_ip": ip,
                            "device_type": device_type,
                            "title": f"No Password / Open Access Alert (Port {finding['port']})",
                            "details": finding["description"]
                        })
                    else:
                        self.alerts.append({
                            "timestamp": datetime.now().isoformat(),
                            "severity": "CRITICAL",
                            "device_ip": ip,
                            "device_type": device_type,
                            "title": f"Default Credential Alert ({finding['credential']})",
                            "details": f"Port {finding['port']} accepted publicly known default login: {finding['credential']}"
                        })

            for cve in matched_cves:
                if cve["severity"] in ["CRITICAL", "HIGH"]:
                    self.alerts.append({
                        "timestamp": datetime.now().isoformat(),
                        "severity": cve["severity"],
                        "device_ip": ip,
                        "device_type": device_type,
                        "title": f"Known CVE Alert: {cve['cve_id']} (CVSS {cve['cvss_score']})",
                        "details": cve["description"]
                    })

        return full_record

    async def execute_network_scan(self, target_cidr: str = None, timeout_discovery: float = 2.5) -> List[Dict[str, Any]]:
        """Run full network discovery, audit, and scoping pipeline without hardcoded subnets."""
        self.is_scanning = True
        self.last_scan_time = datetime.now().isoformat()
        
        # If target CIDR not provided, auto-detect the primary edge subnet
        if not target_cidr:
            target_cidr = get_primary_edge_cidr()

        print(f"[*] Starting IoT Security Audit Scan (Target: {target_cidr})...")

        # Step 1: Multicast Discovery (mDNS & UPnP)
        print("[*] Initiating mDNS & UPnP / SSDP multicast discovery...")
        mdns_results = discover_mdns_devices(timeout_discovery)
        upnp_results = discover_upnp_devices(timeout_discovery)

        # Index mDNS and UPnP by IP
        mdns_by_ip = {}
        for s in mdns_results:
            for addr in s.get("addresses", []):
                mdns_by_ip.setdefault(addr, []).append(s)

        upnp_by_ip = {}
        for u in upnp_results:
            u_ip = u.get("ip")
            if u_ip:
                upnp_by_ip[u_ip] = u

        # Step 2: Assemble Target IP Pool
        arp_hosts = self.get_arp_hosts(edge_only=True)
        target_ips = set(arp_hosts.keys())
        target_ips.update(mdns_by_ip.keys())
        target_ips.update(upnp_by_ip.keys())

        host_ips = get_host_ips()

        # Filter target IPs to target CIDR and actively sweep live hosts
        try:
            network = ipaddress.ip_network(target_cidr, strict=False)
            if network.num_addresses <= 256:
                from app.discovery.port_scanner import check_port
                candidate_hosts = [str(h) for h in network.hosts() if str(h) not in host_ips and is_edge_ip(str(h))]
                probe_ports = [80, 8080, 23, 554, 9999, 5000, 1883]

                async def probe_ip(ip_str):
                    for prt in probe_ports:
                        p, is_open = await check_port(ip_str, prt, timeout=0.25)
                        if is_open:
                            return ip_str
                    return None

                sweep_tasks = [probe_ip(h) for h in candidate_hosts]
                sweep_results = await asyncio.gather(*sweep_tasks)
                active_from_sweep = {res for res in sweep_results if res}
                target_ips.update(active_from_sweep)

            target_ips = {ip for ip in target_ips if ipaddress.ip_address(ip) in network and is_edge_ip(ip)}
        except Exception as e:
            print(f"[!] Warning parsing/sweeping CIDR {target_cidr}: {e}")

        # Exclude host machine IPs and broadcast addresses
        target_ips = {ip for ip in target_ips if ip not in host_ips and not ip.startswith("127.") and not ip.endswith(".255")}

        print(f"[*] Identified {len(target_ips)} target IP(s) for active port scanning and audit: {sorted(list(target_ips))}")

        # Step 3: Deep Scan Each Device Concurrently
        tasks = []
        for ip in sorted(list(target_ips)):
            mac = arp_hosts.get(ip, "")
            tasks.append(self.scan_single_device(
                ip=ip,
                mac=mac,
                mdns_info=mdns_by_ip.get(ip, []),
                upnp_info=upnp_by_ip.get(ip)
            ))

        scanned_devices = await asyncio.gather(*tasks)

        # Step 4: Catalog verified active devices only (thread-safe)
        hotspot_clients = get_hotspot_active_clients()
        hotspot_macs = {c["mac"] for c in hotspot_clients}

        with self._lock:
            scanned_ips = set()
            for dev in scanned_devices:
                dev_ip = dev["ip"]
                if not is_edge_ip(dev_ip):
                    continue

                scanned_ips.add(dev_ip)
                is_alive = self.check_host_alive(dev_ip, open_ports=dev.get("open_ports", []), mac=dev.get("mac"))
                is_hotspot_peer = bool(dev.get("mac") and dev["mac"] in hotspot_macs)
                dev["is_online"] = (is_alive or is_hotspot_peer)

                if dev["open_ports"] or dev["mdns"] or dev["upnp"] or is_hotspot_peer or is_alive:
                    self.inventory[dev_ip] = dev
                elif dev_ip in self.inventory:
                    # Stale lease or disconnected device marked offline
                    self.inventory[dev_ip]["is_online"] = False

            # Verify existing devices in inventory that fall within target_cidr
            for inv_ip, inv_dev in self.inventory.items():
                if not is_edge_ip(inv_ip):
                    continue
                try:
                    if ipaddress.ip_address(inv_ip) in network:
                        if inv_ip not in scanned_ips:
                            alive = self.check_host_alive(
                                inv_ip,
                                open_ports=inv_dev.get("open_ports", []),
                                mac=inv_dev.get("mac")
                            )
                            is_peer = bool(inv_dev.get("mac") and inv_dev["mac"] in hotspot_macs)
                            inv_dev["is_online"] = (alive or is_peer)
                except Exception:
                    pass

            self.is_scanning = False
            cataloged_list = [d for d in self.inventory.values() if is_edge_ip(d.get("ip", ""))]

        print(f"[+] Scan completed! {len(cataloged_list)} active IoT device(s) cataloged.")
        return cataloged_list

    def check_host_alive(self, ip: str, open_ports: List[int] = None, mac: str = None, timeout_ms: int = 300) -> bool:
        """
        True multi-layer presence check.
        Never relies blindly on stale Windows ARP cache.
        """
        if ip in ["127.0.0.1", "localhost", "::1"]:
            return True

        # Layer 1: Authoritative Windows Mobile Hotspot connected peer verification
        is_hotspot_ip = ip.startswith("192.168.137.") or ip.startswith("192.168.173.")
        hotspot_clients = get_hotspot_active_clients()
        is_in_hotspot = any(c["mac"] == mac for c in hotspot_clients) if mac else False
        if is_in_hotspot:
            return True

        # Fast short-circuit: if host is on hotspot IP with known MAC but is no longer
        # registered in the Windows Hotspot client list, it has disconnected from the SoftAP.
        if is_hotspot_ip and mac and not is_in_hotspot:
            return False

        # Layer 2: If known open ports exist, test TCP connect (fast & accurate)
        if open_ports:
            for p in open_ports[:2]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout_ms / 1000.0)
                    res = s.connect_ex((ip, p))
                    s.close()
                    if res == 0:
                        return True
                except Exception:
                    pass

        # Layer 3: Common IoT TCP port probe
        common_ports = [80, 8080, 554, 22, 23]
        for p in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.08)
                res = s.connect_ex((ip, p))
                s.close()
                if res == 0:
                    return True
            except Exception:
                pass

        # Layer 4: ICMP Ping fallback
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
        cmd = ["ping", param, "1", timeout_param, str(timeout_ms), ip]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.6)
            return proc.returncode == 0
        except Exception:
            return False

    def presence_check_cycle(self):
        """Single check cycle for joining and leaving devices across all dynamic edge subnets."""
        if self.is_scanning:
            return

        active_subnets = detect_active_subnets()
        managed_subnets = [s for s in active_subnets if s.get("is_edge")]
        managed_networks = [ipaddress.ip_network(s["cidr"], strict=False) for s in managed_subnets]
        if not managed_networks:
            managed_networks = [
                ipaddress.ip_network("192.168.137.0/24", strict=False),
                ipaddress.ip_network("172.28.10.0/24", strict=False)
            ]

        hotspot_clients = get_hotspot_active_clients()
        hotspot_macs = {c["mac"] for c in hotspot_clients}
        host_ips = get_host_ips()

        # 1. Check existing devices for leaving / reconnecting
        with self._lock:
            items_to_check = list(self.inventory.items())

        for ip, dev in items_to_check:
            # Purge non-edge IP if any leaked into inventory
            if not is_edge_ip(ip):
                with self._lock:
                    self.inventory.pop(ip, None)
                continue

            mac = dev.get("mac", "")
            is_hotspot_ip = ip.startswith("192.168.137.") or ip.startswith("192.168.173.")
            is_hotspot_peer = bool(mac and mac in hotspot_macs)

            is_alive = self.check_host_alive(ip, open_ports=dev.get("open_ports", []), mac=mac)
            was_online = bool(dev.get("is_online"))

            if is_alive or is_hotspot_peer:
                with self._lock:
                    dev["is_online"] = True
                    dev["missed_pings"] = 0
                    dev["last_seen"] = datetime.now().isoformat()
                    if not was_online:
                        self.alerts.append({
                            "timestamp": datetime.now().isoformat(),
                            "severity": "INFO",
                            "device_ip": ip,
                            "device_type": dev.get("device_type", "Unknown"),
                            "title": f"Device Reconnected: {ip}",
                            "details": f"IoT Device {ip} ({dev.get('device_type')}) has reconnected to the network."
                        })
            else:
                with self._lock:
                    dev["missed_pings"] = dev.get("missed_pings", 0) + 1
                    # Immediate offline detection for hotspot devices or missed_pings >= 1
                    should_mark_offline = (is_hotspot_ip and not is_hotspot_peer) or (dev["missed_pings"] >= 1)
                    if should_mark_offline and was_online:
                        dev["is_online"] = False
                        self.alerts.append({
                            "timestamp": datetime.now().isoformat(),
                            "severity": "WARNING",
                            "device_ip": ip,
                            "device_type": dev.get("device_type", "Unknown"),
                            "title": f"Device Left Network (Offline): {ip}",
                            "details": f"IoT Device {ip} ({dev.get('device_type')}) stopped responding to network heartbeat."
                        })

        # 2. Check for newly joined devices across edge subnets
        arp_hosts = self.get_arp_hosts(edge_only=True)
        for ip, mac in arp_hosts.items():
            if not is_edge_ip(ip):
                continue

            with self._lock:
                already_known = ip in self.inventory

            if ip in host_ips or already_known or ip.endswith(".255"):
                continue

            # Check if IP falls within managed subnets
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not any(ip_obj in net for net in managed_networks):
                    continue
            except Exception:
                continue

            # Only scan if host is confirmed alive or in active hotspot client list
            is_hotspot_peer = bool(mac in hotspot_macs)
            if is_hotspot_peer or self.check_host_alive(ip, mac=mac):
                try:
                    new_dev = asyncio.run(self.scan_single_device(ip, mac))
                    if new_dev["open_ports"] or new_dev["mdns"] or new_dev["upnp"] or is_hotspot_peer:
                        new_dev["is_online"] = True
                        with self._lock:
                            self.inventory[ip] = new_dev
                            self.alerts.append({
                                "timestamp": datetime.now().isoformat(),
                                "severity": "INFO",
                                "device_ip": ip,
                                "device_type": new_dev.get("device_type", "Unknown"),
                                "title": f"New IoT Device Joined: {ip}",
                                "details": f"Discovered new device {ip} ({new_dev['device_type']} - {new_dev['vendor']}) on edge subnet."
                            })
                except Exception:
                    pass

    def start_presence_monitor(self, interval_seconds: float = 4.0):
        """Start recurring background watcher for device join/leave events."""
        if self.presence_monitor_running:
            return
        self.presence_monitor_running = True
        import threading
        import time
        def _loop():
            while self.presence_monitor_running:
                try:
                    time.sleep(interval_seconds)
                    self.presence_check_cycle()
                except Exception:
                    pass
        t = threading.Thread(target=_loop, daemon=True)
        t.start()

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Compute system-wide dashboard metrics including traffic and online states."""
        with self._lock:
            devices = [d for d in self.inventory.values() if is_edge_ip(d.get("ip", ""))]
        total = len(devices)
        online_count = sum(1 for d in devices if d.get("is_online") is True)
        offline_count = total - online_count
        vulnerable_count = sum(1 for d in devices if d.get("risk_level") in ["CRITICAL", "HIGH"])
        unprotected_count = sum(1 for d in devices if d.get("default_credentials_found") or d.get("is_open_access"))
        quarantine_count = sum(1 for d in devices if d.get("scoping_policy", {}).get("quarantine_required"))
        
        # Breakdown by device type
        by_type = {}
        for d in devices:
            t = d.get("device_type", "Generic IoT Device")
            by_type[t] = by_type.get(t, 0) + 1

        traffic = GLOBAL_TRAFFIC_METER.get_snapshot()

        return {
            "total_devices": total,
            "online_devices": online_count,
            "offline_devices": offline_count,
            "vulnerable_devices": vulnerable_count,
            "default_passwords_found": unprotected_count,
            "quarantine_recommended": quarantine_count,
            "device_types": by_type,
            "last_scan_time": self.last_scan_time,
            "vlan_groups": group_devices_by_vlan(devices),
            "traffic": traffic
        }
