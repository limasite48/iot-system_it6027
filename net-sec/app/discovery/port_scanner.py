"""
Asynchronous TCP Port Scanner (net-sec)
Efficiently scans standard IoT ports across subnets or specific target IPs.
"""

import asyncio
import socket
from typing import List, Dict, Tuple

COMMON_IOT_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet (Mirai, BusyBox)
    80,    # HTTP
    443,   # HTTPS
    554,   # RTSP (IP Cameras, video feeds)
    1883,  # MQTT (IoT telemetry)
    5000,  # UPnP / IoT Gateway
    8080,  # HTTP Alt (IP Webcam default)
    8081,  # HTTP Alt (Camera secondary stream)
    8089,  # HTTP Alt
    8443,  # HTTPS Alt
    8888,  # HTTP Alt (Embedded webcams)
    9999   # Smart Plug / Xiongmai IoT control
]

async def check_port(ip: str, port: int, timeout: float = 1.0) -> Tuple[int, bool]:
    """Test TCP connection to a specific port on an IP."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port, True
    except (asyncio.TimeoutError, OSError):
        return port, False

async def scan_host_ports(ip: str, ports: List[int] = None, timeout: float = 1.0) -> List[int]:
    """Scan all specified ports on a single host concurrently."""
    if ports is None:
        ports = COMMON_IOT_PORTS
    tasks = [check_port(ip, p, timeout) for p in ports]
    results = await asyncio.gather(*tasks)
    return [p for p, is_open in results if is_open]

async def scan_subnet_hosts(ip_list: List[str], ports: List[int] = None, timeout: float = 0.6) -> Dict[str, List[int]]:
    """Scan a list of IP addresses concurrently."""
    results = {}
    tasks = [scan_host_ports(ip, ports, timeout) for ip in ip_list]
    scan_results = await asyncio.gather(*tasks)
    for ip, open_ports in zip(ip_list, scan_results):
        if open_ports:
            results[ip] = open_ports
    return results

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(f"[*] Scanning {target} on common IoT ports...")
    open_p = asyncio.run(scan_host_ports(target))
    print(f"[+] Open ports on {target}: {open_p}")
