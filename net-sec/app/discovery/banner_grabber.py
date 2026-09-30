"""
IoT Service Banner Grabber (net-sec)
Interrogates open IoT ports to extract server headers, authentication realms,
HTML titles, RTSP banners, and Telnet prompts.
"""

import socket
import re
import asyncio
import httpx
from typing import Dict, Any, List

def grab_http_banner(ip: str, port: int, timeout: float = 1.5) -> Dict[str, Any]:
    """Interrogate HTTP/HTTPS service for banners, realm, and page title."""
    banner_info = {
        "server": "",
        "auth_realm": "",
        "title": "",
        "powered_by": "",
        "raw_headers": {}
    }
    schemes = ["http"]
    if port in [443, 8443]:
        schemes = ["https", "http"]
    else:
        schemes = ["http", "https"]

    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}/"
        try:
            with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as client:
                resp = client.get(url)
                banner_info["server"] = resp.headers.get("Server", "")
                banner_info["powered_by"] = resp.headers.get("X-Powered-By", "")
                banner_info["raw_headers"] = dict(resp.headers)
                
                # Check for WWW-Authenticate realm
                auth_header = resp.headers.get("WWW-Authenticate", "")
                if auth_header:
                    realm_match = re.search(r'realm="([^"]+)"', auth_header, re.IGNORECASE)
                    if realm_match:
                        banner_info["auth_realm"] = realm_match.group(1)
                    else:
                        banner_info["auth_realm"] = auth_header

                # Extract HTML title
                title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    banner_info["title"] = title_match.group(1).strip()
                return banner_info
        except Exception:
            continue
    return banner_info

def grab_rtsp_banner(ip: str, port: int = 554, timeout: float = 1.5) -> Dict[str, str]:
    """Send RTSP OPTIONS query to grab RTSP server banners."""
    result = {"server": "", "public_methods": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        request = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: IoTSecurityScanner/1.0\r\n\r\n"
        sock.sendall(request.encode("utf-8"))
        response = sock.recv(2048).decode("utf-8", errors="ignore")
        for line in response.split("\r\n"):
            if line.lower().startswith("server:"):
                result["server"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("public:"):
                result["public_methods"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    finally:
        sock.close()
    return result

def grab_telnet_banner(ip: str, port: int = 23, timeout: float = 1.5) -> str:
    """Connect to Telnet port and read the initial welcome prompt."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    banner = ""
    try:
        sock.connect((ip, port))
        data = sock.recv(1024)
        banner = data.decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    finally:
        sock.close()
    return banner

def grab_mqtt_banner(ip: str, port: int = 1883, timeout: float = 1.5) -> Dict[str, Any]:
    """Send minimal MQTT CONNECT packet and observe response."""
    result = {"open": False, "anonymous_allowed": False}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        # MQTT 3.1.1 CONNECT packet with client_id="sec-scanner"
        # Fixed header: 0x10, remaining length
        connect_packet = bytearray([
            0x10, 0x18,        # Connect, remaining length 24
            0x00, 0x04, 0x4D, 0x51, 0x54, 0x54,  # Protocol Name "MQTT"
            0x04,              # Protocol Level 4 (3.1.1)
            0x02,              # Connect Flags (Clean Session only)
            0x00, 0x3C,        # Keep Alive (60s)
            0x00, 0x0C,        # Client ID length 12
            0x73, 0x65, 0x63, 0x2D, 0x73, 0x63, 0x61, 0x6E, 0x6E, 0x65, 0x72, 0x31 # "sec-scanner1"
        ])
        sock.sendall(connect_packet)
        resp = sock.recv(10)
        if len(resp) >= 4 and resp[0] == 0x20:  # CONNACK packet
            result["open"] = True
            return_code = resp[3]
            if return_code == 0:
                result["anonymous_allowed"] = True
            result["return_code"] = return_code
    except Exception:
        pass
    finally:
        sock.close()
    return result

def inspect_all_banners(ip: str, open_ports: List[int]) -> Dict[str, Any]:
    """Inspect all open ports on a host and collect comprehensive banners."""
    banners = {}
    for port in open_ports:
        if port in [80, 443, 3000, 3001, 5000, 8001, 8002, 8080, 8081, 8089, 8443, 8888, 9999]:
            banners[f"http_{port}"] = grab_http_banner(ip, port)
        elif port in [554]:
            banners["rtsp_554"] = grab_rtsp_banner(ip, port)
        elif port == 23:
            banners["telnet_23"] = grab_telnet_banner(ip, port)
        elif port == 1883:
            banners["mqtt_1883"] = grab_mqtt_banner(ip, port)
    return banners

if __name__ == "__main__":
    import sys
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(f"[*] Grabbing banners from {target_ip} on port 8080...")
    print(grab_http_banner(target_ip, 8080))
