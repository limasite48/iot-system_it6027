"""
UPnP / SSDP Discovery Scanner (net-sec)
Discovers IoT devices via SSDP M-SEARCH multicast queries and parses device XML descriptors.
"""

import socket
import struct
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import httpx
from typing import List, Dict, Any

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

MSEARCH_QUERY = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
)

def parse_ssdp_response(raw_data: str) -> Dict[str, str]:
    headers = {}
    lines = raw_data.split("\r\n")
    for line in lines[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip().upper()] = val.strip()
    return headers

def parse_upnp_xml(xml_content: str) -> Dict[str, str]:
    """Extract device metadata from UPnP XML root."""
    metadata = {}
    try:
        # Strip XML namespaces for easier traversal
        clean_xml = "".join([line for line in xml_content.splitlines() if not line.strip().startswith("<?xml")])
        root = ET.fromstring(clean_xml)
        
        # Helper to find tag ignoring namespace
        def find_text_any_ns(node, tag):
            for elem in node.iter():
                if elem.tag.endswith(tag) and elem.text:
                    return elem.text.strip()
            return ""

        metadata["friendly_name"] = find_text_any_ns(root, "friendlyName")
        metadata["manufacturer"] = find_text_any_ns(root, "manufacturer")
        metadata["model_name"] = find_text_any_ns(root, "modelName")
        metadata["model_number"] = find_text_any_ns(root, "modelNumber")
        metadata["firmware_version"] = find_text_any_ns(root, "firmwareVersion")
        metadata["serial_number"] = find_text_any_ns(root, "serialNumber")
        metadata["device_type"] = find_text_any_ns(root, "deviceType")
    except Exception:
        pass
    return metadata

def discover_upnp_devices(timeout_seconds: float = 3.0) -> List[Dict[str, Any]]:
    """Broadcasts SSDP M-SEARCH and collects device descriptors."""
    discovered = []
    seen_locations = set()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.5)

    try:
        # Send M-SEARCH broadcast
        sock.sendto(MSEARCH_QUERY.encode("utf-8"), (SSDP_ADDR, SSDP_PORT))
        start_time = time.time()

        while time.time() - start_time < timeout_seconds:
            try:
                data, (ip, port) = sock.recvfrom(4096)
                raw_text = data.decode("utf-8", errors="ignore")
                headers = parse_ssdp_response(raw_text)
                location = headers.get("LOCATION", "")
                
                if location and location not in seen_locations:
                    seen_locations.add(location)
                    parsed_url = urlparse(location)
                    device_ip = parsed_url.hostname or ip

                    entry = {
                        "ip": device_ip,
                        "ssdp_port": port,
                        "location": location,
                        "server": headers.get("SERVER", ""),
                        "st": headers.get("ST", ""),
                        "usn": headers.get("USN", ""),
                        "xml_meta": {}
                    }

                    # Fetch XML description
                    try:
                        resp = httpx.get(location, timeout=2.0)
                        if resp.status_code == 200:
                            entry["xml_meta"] = parse_upnp_xml(resp.text)
                    except Exception:
                        pass

                    discovered.append(entry)
            except socket.timeout:
                continue
            except Exception:
                break
    finally:
        sock.close()

    return discovered

if __name__ == "__main__":
    print("[*] Scanning for UPnP / SSDP devices for 3 seconds...")
    devs = discover_upnp_devices(3.0)
    print(f"[+] Found {len(devs)} UPnP devices:")
    for d in devs:
        meta = d["xml_meta"]
        print(f"  - {d['ip']} | Server: {d['server']} | Model: {meta.get('model_name')} | Vendor: {meta.get('manufacturer')}")
