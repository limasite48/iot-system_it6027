"""
mDNS / Zeroconf Discovery Listener (net-sec)
Discovers IoT devices advertising mDNS services on the local network.
"""

import time
import socket
from typing import Dict, Any, List
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

IOT_SERVICE_TYPES = [
    "_http._tcp.local.",
    "_rtsp._tcp.local.",
    "_camera._tcp.local.",
    "_axis-video._tcp.local.",
    "_googlecast._tcp.local.",
    "_apple-mobdev2._tcp.local.",
    "_android-remote._tcp.local.",
    "_smartplug._tcp.local.",
    "_mqtt._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_workstation._tcp.local."
]

class MDNSIotListener(ServiceListener):
    def __init__(self):
        self.discovered_services: List[Dict[str, Any]] = []

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self._process_service(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self._process_service(zc, type_, name)

    def _process_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        try:
            info = zc.get_service_info(type_, name, timeout=1500)
            if not info:
                return

            addresses = [socket.inet_ntoa(addr) for addr in info.addresses if len(addr) == 4]
            if not addresses:
                return

            properties = {}
            for k, v in info.properties.items():
                k_str = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
                v_str = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
                properties[k_str] = v_str

            entry = {
                "name": name,
                "type": type_,
                "server": info.server,
                "port": info.port,
                "addresses": addresses,
                "properties": properties
            }
            # Deduplicate by name and type
            if not any(s["name"] == name and s["type"] == type_ for s in self.discovered_services):
                self.discovered_services.append(entry)
        except Exception:
            pass

def discover_mdns_devices(timeout_seconds: float = 3.0) -> List[Dict[str, Any]]:
    """Scan the local network for mDNS IoT services during timeout_seconds."""
    listener = MDNSIotListener()
    try:
        zc = Zeroconf()
        browsers = [ServiceBrowser(zc, s_type, listener) for s_type in IOT_SERVICE_TYPES]
        time.sleep(timeout_seconds)
        zc.close()
    except Exception as e:
        print(f"[!] mDNS discovery error: {e}")
    return listener.discovered_services

if __name__ == "__main__":
    print("[*] Listening for mDNS IoT devices for 3 seconds...")
    services = discover_mdns_devices(3.0)
    print(f"[+] Found {len(services)} mDNS services:")
    for s in services:
        print(f"  - {s['name']} ({s['type']}) at {s['addresses']}:{s['port']} props={s['properties']}")
