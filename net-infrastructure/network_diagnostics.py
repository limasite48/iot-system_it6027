#!/usr/bin/env python3
"""
IoT Network Diagnostics Utility (net-infrastructure)
Detects active network interfaces, discovers connected devices via ARP cache,
and verifies network reachability on the IoT Edge Subnet.
"""

import sys
import re
import socket
import subprocess
import platform

def get_local_interfaces():
    """Retrieve active IPv4 addresses on the host system."""
    interfaces = []
    try:
        if platform.system() == "Windows":
            cmd = ["powershell", "-NoProfile", "-Command",
                   "Get-NetIPAddress -AddressFamily IPv4 | "
                   "Select-Object IPAddress, InterfaceAlias, InterfaceIndex | "
                   "ConvertTo-Json -Compress"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                import json
                data = json.loads(res.stdout)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    ip = item.get("IPAddress", "")
                    alias = item.get("InterfaceAlias", "")
                    if not ip.startswith("127."):
                        interfaces.append({"ip": ip, "name": alias})
    except Exception as e:
        print(f"[!] Warning retrieving interfaces via PowerShell: {e}")
        # Fallback to socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            interfaces.append({"ip": ip, "name": "Default Socket Interface"})
        except Exception:
            pass
    return interfaces

def get_arp_neighbors():
    """Extract ARP entries to find connected physical devices."""
    neighbors = []
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
        # Windows arp -a format:
        #   Internet Address      Physical Address      Type
        #   192.168.137.2         xx-xx-xx-xx-xx-xx     dynamic
        pattern = re.compile(r"^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9a-fA-F-]+)\s+(\w+)", re.MULTILINE)
        for match in pattern.finditer(output):
            ip, mac, entry_type = match.groups()
            # Filter out broadcast and multicast entries
            if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239."):
                continue
            neighbors.append({
                "ip": ip,
                "mac": mac.replace("-", ":").upper(),
                "type": entry_type
            })
    except Exception as e:
        print(f"[!] Warning reading ARP table: {e}")
    return neighbors

def ping_host(ip, timeout_ms=800):
    """Ping an IP address to test connectivity."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
    cmd = ["ping", param, "1", timeout_param, str(timeout_ms), ip]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return proc.returncode == 0
    except Exception:
        return False

def main():
    print("=" * 65)
    print("        IoT Network Diagnostics - Edge Subnet Discovery       ")
    print("=" * 65)

    print("\n[*] Host Network Interfaces:")
    interfaces = get_local_interfaces()
    hotspot_found = False
    for iface in interfaces:
        mark = " (Hotspot Default Subnet)" if iface["ip"].startswith("192.168.137.") else ""
        print(f"  * {iface['ip']:<18} | Interface: {iface['name']}{mark}")
        if iface["ip"].startswith("192.168.137."):
            hotspot_found = True

    if not hotspot_found:
        print("\n[i] Note: No 192.168.137.x address found. If using Mobile Hotspot,")
        print("    please ensure Mobile Hotspot is turned ON in Windows Settings.")
    else:
        print("\n[+] Mobile Hotspot Edge Subnet active at 192.168.137.1")

    print("\n[*] Discovering Connected Devices (ARP Table)...")
    neighbors = get_arp_neighbors()
    if not neighbors:
        print("  [!] No neighbors currently recorded in ARP table.")
        print("      Ensure your smartphone is connected to the Wi-Fi Hotspot.")
        return

    print(f"  {'IP Address':<18} {'MAC Address':<20} {'Status':<10} {'Type'}")
    print("  " + "-" * 55)
    for n in neighbors:
        is_alive = ping_host(n["ip"])
        status = "ALIVE" if is_alive else "NO RESPONSE"
        print(f"  {n['ip']:<18} {n['mac']:<20} {status:<10} {n['type']}")

    print("\n[+] Diagnostics completed.\n")

if __name__ == "__main__":
    main()
