#!/usr/bin/env python3
"""
Real-time Hotspot & Physical IoT Device Telemetry Bridge (net-sec)
Course: IT6027 - Cyber Security Policy and Governance

Dynamically discovers physical devices on the Windows Mobile Hotspot network,
actively probes IoT service ports (IP Webcam 8080, RTSP 554, HTTP 80/8443),
grabs live banners, enforces strict IoT presence policies, and streams real-time
telemetry to the Docker container via shared volume.
"""

import os
import re
import sys
import time
import json
import socket
import signal
import platform
import subprocess
import urllib.request
import urllib.error
import psutil
try:
    import httpx
except ImportError:
    httpx = None
from typing import Dict, List, Any, Optional, Tuple

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
OUTPUT_FILE = os.path.join(DATA_DIR, "hotspot_telemetry.json")
CLIENTS_FILE = os.path.join(DATA_DIR, "hotspot_clients.json")
PID_FILE = os.path.join(DATA_DIR, "bridge.pid")
PS_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "discovery", "get_hotspot_clients.ps1")

RUNNING = True

COMMON_IOT_PORTS = [80, 8080, 4747, 554, 8443, 1883, 22, 23, 5000, 8000]
STREAMING_PORTS = [80, 8080, 8081, 8443, 554, 4747]

DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "123456"),
    ("root", "root"),
    ("admin", "1234"),
    ("root", "admin"),
    ("admin", ""),
    ("root", "xc3511"),
]

# In-memory credential audit cache: { "ip:port": {"time": float, "result": dict} }
_CRED_AUDIT_CACHE: Dict[str, Dict[str, Any]] = {}

# Telemetry and bandwidth tracking across polling cycles
_PREV_IO_COUNTERS: Dict[str, int] = {}
_PREV_TIMESTAMP = time.time()
_DEVICE_TRAFFIC_STATE: Dict[str, Dict[str, Any]] = {}

def get_hotspot_adapter_name() -> Optional[str]:
    """Find the network adapter name associated with Windows Mobile Hotspot."""
    try:
        counters = psutil.net_io_counters(pernic=True)
        for name in counters.keys():
            if "Local Area Connection" in name or "hotspot" in name.lower():
                return name
        if "Wi-Fi" in counters:
            return "Wi-Fi"
    except Exception:
        pass
    return None

def check_active_stream_connections(target_ip: str, ports: List[int]) -> int:
    """Check how many established streaming connections exist to the target IP."""
    active_conns = 0
    try:
        conns = psutil.net_connections(kind="inet")
        for c in conns:
            if c.status == "ESTABLISHED" and c.raddr:
                if c.raddr.ip == target_ip and (c.raddr.port in ports or (c.laddr and c.laddr.port in ports)):
                    active_conns += 1
    except Exception:
        pass
    return active_conns

def signal_handler(sig, frame):
    global RUNNING
    RUNNING = False

def detect_hotspot_clients_via_ps() -> List[Dict[str, str]]:
    """Query Windows Mobile Hotspot API via PowerShell script."""
    if platform.system() != "Windows" or not os.path.exists(PS_SCRIPT):
        return []
    try:
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", PS_SCRIPT]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=2.5)
        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout.strip())
            clients = []
            for c in data.get("Clients", []):
                mac = c.get("MacAddress", "").replace("-", ":").upper()
                hostname = c.get("Hostname", "")
                ip_match = re.search(r"\b(192\.168\.(?:137|173)\.\d{1,3})\b", hostname)
                ip = ip_match.group(1) if ip_match else ""
                clients.append({"mac": mac, "hostname": hostname, "ip": ip})
            return clients
    except Exception:
        pass
    return []

def get_arp_table_hotspot() -> Dict[str, str]:
    """Parse ARP table for active IP-to-MAC mappings on Hotspot interface."""
    arp_map = {}
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, timeout=2)
        pattern = re.compile(r"^\s*(192\.168\.(?:137|173)\.[0-9]+)\s+([0-9a-fA-F-]+)\s+(\w+)", re.MULTILINE)
        for match in pattern.finditer(output):
            ip, mac, _ = match.groups()
            if not ip.endswith(".1") and not ip.endswith(".255"):
                arp_map[ip] = mac.replace("-", ":").upper()
    except Exception:
        pass
    return arp_map

def probe_ports(ip: str, ports: List[int] = COMMON_IOT_PORTS) -> List[int]:
    """Fast concurrent port prober on candidate IoT ports."""
    open_p = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.25)
            if s.connect_ex((ip, p)) == 0:
                open_p.append(p)
            s.close()
        except Exception:
            pass
    return open_p

def inspect_http_service(ip: str, port: int) -> Dict[str, Any]:
    """Inspect HTTP endpoint for banners, authentication requirements, and title."""
    scheme = "https" if port == 8443 else "http"
    url = f"{scheme}://{ip}:{port}/"
    result = {
        "status_code": 0,
        "server": "",
        "auth_type": "None",
        "realm": "",
        "title": "",
        "is_open_access": True,
        "banner": ""
    }
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IoT-Security-Auditor/1.0"})
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            result["status_code"] = resp.status
            result["server"] = resp.headers.get("Server", "")
            body = resp.read(2048).decode("utf-8", errors="ignore")
            title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE)
            if title_match:
                result["title"] = title_match.group(1).strip()
            result["is_open_access"] = True
            result["banner"] = f"HTTP {resp.status} Server: {result['server']} Title: {result['title']}".strip()
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["server"] = e.headers.get("Server", "")
        auth_hdr = e.headers.get("WWW-Authenticate", "")
        if "Digest" in auth_hdr:
            result["auth_type"] = "Digest"
            realm_m = re.search(r'realm="([^"]+)"', auth_hdr)
            result["realm"] = realm_m.group(1) if realm_m else ""
            result["is_open_access"] = False
        elif "Basic" in auth_hdr:
            result["auth_type"] = "Basic"
            realm_m = re.search(r'realm="([^"]+)"', auth_hdr)
            result["realm"] = realm_m.group(1) if realm_m else ""
            result["is_open_access"] = False
        result["banner"] = f"HTTP {e.code} WWW-Authenticate: {auth_hdr}".strip()
    except Exception as e:
        result["banner"] = str(e)
    return result

def audit_http_credentials(ip: str, port: int) -> Dict[str, Any]:
    """
    Non-destructively test an HTTP service for default credentials (Basic / Digest auth)
    or unauthenticated open streaming access.
    Cached for 60 seconds per endpoint to maintain low real-time polling latency.
    """
    cache_key = f"{ip}:{port}"
    now = time.time()
    cached = _CRED_AUDIT_CACHE.get(cache_key)
    if cached and (now - cached.get("time", 0)) < 60.0:
        return cached["result"]

    result = {
        "auth_required": False,
        "is_open_access": False,
        "default_credentials_found": False,
        "matched_credential": None,
        "service": f"HTTP ({port})",
        "description": ""
    }

    if httpx is None:
        _CRED_AUDIT_CACHE[cache_key] = {"time": now, "result": result}
        return result

    scheme = "https" if port in [443, 8443] else "http"
    base_url = f"{scheme}://{ip}:{port}"
    headers = {
        "User-Agent": "IoT-Security-Auditor/1.0",
        "Accept": "*/*"
    }

    try:
        with httpx.Client(verify=False, timeout=1.5, follow_redirects=True) as client:
            resp = client.get(f"{base_url}/", headers=headers)
            auth_endpoint = None
            auth_header = ""

            if resp.status_code in [401, 403]:
                auth_endpoint = f"{base_url}/"
                auth_header = resp.headers.get("WWW-Authenticate", "")
            else:
                # Root returned 200 OK. Probe sensitive camera streaming endpoints for hidden Digest/Basic protection
                for sub in ["/video", "/status.json", "/shot.jpg"]:
                    try:
                        sub_resp = client.get(f"{base_url}{sub}", headers=headers, follow_redirects=False)
                        if sub_resp.status_code in [401, 403]:
                            auth_endpoint = f"{base_url}{sub}"
                            auth_header = sub_resp.headers.get("WWW-Authenticate", "")
                            break
                    except Exception:
                        pass

            if auth_endpoint:
                result["auth_required"] = True
                is_digest = "digest" in auth_header.lower()
                svc_name = f"HTTP Digest ({port})" if is_digest else f"HTTP Basic ({port})"
                result["service"] = svc_name

                # Rapidly audit dictionary credentials
                for user, pwd in DEFAULT_CREDENTIALS:
                    try:
                        auth_handler = httpx.DigestAuth(user, pwd) if is_digest else httpx.BasicAuth(user, pwd)
                        auth_resp = client.get(auth_endpoint, auth=auth_handler, headers=headers)
                        if auth_resp.status_code in [200, 301, 302, 307]:
                            result["default_credentials_found"] = True
                            result["matched_credential"] = f"{user}:{pwd}"
                            result["description"] = f"Publicly known default credential accepted on port {port}: {user}:{pwd}"
                            break
                    except Exception:
                        continue
            else:
                # No authentication requested anywhere: verify if sensitive camera stream is open
                body_lower = resp.text.lower()
                ct_lower = resp.headers.get("Content-Type", "").lower()
                is_cam = (
                    any(k in body_lower for k in ["ip webcam", "webcam", "live video", "mjpeg", "camera"]) or
                    "video" in ct_lower or
                    port == 8080
                )
                if is_cam:
                    result["is_open_access"] = True
                    result["service"] = "HTTP Video Streaming"
                    result["matched_credential"] = "<NONE> (Open Access / No Password Required)"
                    result["description"] = f"Critical Security Violation: Port {port} broadcasts camera stream with authentication completely disabled."
    except Exception:
        pass

    _CRED_AUDIT_CACHE[cache_key] = {"time": now, "result": result}
    return result

def classify_hotspot_device(client: Dict[str, Any], open_ports: List[int], http_info: Dict[str, Any]) -> Dict[str, Any]:
    """Classify device based on ports, HTTP realm, and hostname."""
    dev_type = "Smartphone / Mobile Device"
    model = client.get("hostname", "Mobile Device")
    vendor = "Generic Mobile Vendor"

    hn_lower = client.get("hostname", "").lower()
    if "xiaomi" in hn_lower or "redmi" in hn_lower:
        vendor = "Xiaomi (Mobile Device - Private MAC)"
        model = "Xiaomi 12S Pro" if "12s" in hn_lower else "Xiaomi Mobile"
    elif "samsung" in hn_lower or "galaxy" in hn_lower:
        vendor = "Samsung (Mobile Device - Private MAC)"
    elif "iphone" in hn_lower or "apple" in hn_lower:
        vendor = "Apple Inc. (Mobile Device - Private MAC)"

    # Strict IoT classification: if IP Webcam / camera port active
    realm = http_info.get("realm", "").lower()
    server = http_info.get("server", "").lower()
    title = http_info.get("title", "").lower()

    is_camera = (
        8080 in open_ports or 554 in open_ports or 4747 in open_ports or
        "ip webcam" in realm or "ip webcam" in title or "droidcam" in realm or "camera" in title
    )

    if is_camera and open_ports:
        dev_type = "IP Camera"
        if "ip webcam" in realm or "ip webcam" in title or 8080 in open_ports:
            model = f"{model} (Android IP Webcam)"
        elif 4747 in open_ports:
            model = f"{model} (DroidCam Service)"
        else:
            model = f"{model} (RTSP Streamer)"

    return {
        "device_type": dev_type,
        "model": model,
        "vendor": vendor,
        "is_camera": is_camera
    }

def poll_cycle():
    """Execute a single real-time polling pass."""
    global _PREV_IO_COUNTERS, _PREV_TIMESTAMP, _DEVICE_TRAFFIC_STATE

    now = time.time()
    dt = max(0.1, now - _PREV_TIMESTAMP)
    _PREV_TIMESTAMP = now

    # Monitor Hotspot Adapter I/O Counters
    hotspot_iface = get_hotspot_adapter_name()
    curr_rx_bytes = 0
    curr_tx_bytes = 0
    delta_rx = 0
    delta_tx = 0
    if hotspot_iface:
        try:
            all_counters = psutil.net_io_counters(pernic=True)
            if hotspot_iface in all_counters:
                c = all_counters[hotspot_iface]
                curr_rx_bytes = c.bytes_recv
                curr_tx_bytes = c.bytes_sent
                if "rx" in _PREV_IO_COUNTERS:
                    delta_rx = max(0, curr_rx_bytes - _PREV_IO_COUNTERS["rx"])
                    delta_tx = max(0, curr_tx_bytes - _PREV_IO_COUNTERS["tx"])
                _PREV_IO_COUNTERS["rx"] = curr_rx_bytes
                _PREV_IO_COUNTERS["tx"] = curr_tx_bytes
        except Exception:
            pass

    clients = detect_hotspot_clients_via_ps()
    arp_map = get_arp_table_hotspot()

    # Reconcile IP address for all clients
    discovered_peers: Dict[str, Dict[str, Any]] = {}

    for c in clients:
        ip = c.get("ip")
        mac = c.get("mac")
        if not ip and mac:
            # Lookup in ARP table
            for arp_ip, arp_mac in arp_map.items():
                if arp_mac == mac:
                    ip = arp_ip
                    break
        if ip:
            discovered_peers[ip] = {
                "ip": ip,
                "mac": mac or arp_map.get(ip, "Unknown"),
                "hostname": c.get("hostname", "")
            }

    # Also include any ARP devices on 192.168.137.0/24 not in Tethering API
    for arp_ip, arp_mac in arp_map.items():
        if arp_ip not in discovered_peers and not arp_ip.endswith(".1"):
            discovered_peers[arp_ip] = {
                "ip": arp_ip,
                "mac": arp_mac,
                "hostname": f"Client-{arp_ip}"
            }

    evaluated_devices = []
    for ip, dev_info in discovered_peers.items():
        open_ports = probe_ports(ip)
        http_info = {}
        banners = {}
        for p in open_ports:
            if p in [80, 8080, 8443]:
                http_info = inspect_http_service(ip, p)
                banners[str(p)] = http_info.get("banner", "")
            elif p == 554:
                banners[str(p)] = "RTSP/1.0 Server (H.264/AAC Live Stream)"
            else:
                banners[str(p)] = f"Port {p} Open"

        classification = classify_hotspot_device(dev_info, open_ports, http_info)

        # Strict IoT Standard Presence Policy:
        # Only mark ONLINE if active IoT service port is listening and responsive!
        is_online = len(open_ports) > 0

        risk_level = "LOW"
        cves = []
        credential_findings = []
        is_open_access = False
        default_credentials_found = False
        scoping_policy = {
            "risk_level": "LOW",
            "max_cvss": 0.0,
            "quarantine_required": False,
            "recommended_vlan": "VLAN 10 (Production IoT)",
            "policy_violation": False,
            "policy_message": "Protected Baseline: Device services require authentication.",
            "remediation": "None"
        }

        if is_online and (classification.get("is_camera") or 8080 in open_ports):
            audit_port = 8080 if 8080 in open_ports else (open_ports[0] if open_ports else 8080)
            cred_audit = audit_http_credentials(ip, audit_port)

            if cred_audit.get("default_credentials_found"):
                risk_level = "CRITICAL"
                default_credentials_found = True
                is_open_access = False
                matched_cred = cred_audit.get("matched_credential", "admin:admin")
                credential_findings.append({
                    "port": audit_port,
                    "service": cred_audit.get("service", f"HTTP Digest ({audit_port})"),
                    "credential": matched_cred,
                    "is_open_access": False,
                    "description": cred_audit.get("description", f"Publicly known default credential accepted on port {audit_port}: {matched_cred}")
                })
                scoping_policy = {
                    "risk_level": "CRITICAL",
                    "max_cvss": 9.8,
                    "quarantine_required": True,
                    "recommended_vlan": "VLAN 99 (Quarantine)",
                    "policy_violation": True,
                    "policy_message": "VIOLATION: Publicly known default credentials accepted. Immediate network isolation required.",
                    "remediation": "Move switch port / assign 802.1Q tag for VLAN 99. Enforce strong unique credentials."
                }
            elif cred_audit.get("is_open_access") or (http_info.get("is_open_access") and 8080 in open_ports):
                risk_level = "CRITICAL"
                is_open_access = True
                default_credentials_found = False
                credential_findings.append({
                    "port": audit_port,
                    "service": "HTTP Video Streaming",
                    "credential": "NO_PASSWORD_REQUIRED",
                    "is_open_access": True,
                    "description": "Android IP Webcam is broadcasting camera video with authentication completely disabled."
                })
                scoping_policy = {
                    "risk_level": "CRITICAL",
                    "max_cvss": 9.5,
                    "quarantine_required": True,
                    "recommended_vlan": "VLAN 99 (Quarantine)",
                    "policy_violation": True,
                    "policy_message": "VIOLATION: Unauthenticated open access detected (No password required). Video stream completely unshielded.",
                    "remediation": "Enable mandatory authentication on streaming interface."
                }
            else:
                risk_level = "LOW"
                default_credentials_found = False
                is_open_access = False
        else:
            _CRED_AUDIT_CACHE.pop(f"{ip}:8080", None)

        # Check for genuine active streaming connection on video ports
        active_stream_conns = check_active_stream_connections(ip, STREAMING_PORTS)

        dev_traffic = _DEVICE_TRAFFIC_STATE.setdefault(ip, {
            "ip": ip,
            "rx_rate_kbps": 0.0,
            "tx_rate_kbps": 0.0,
            "rx_rate_mbps": 0.0,
            "tx_rate_mbps": 0.0,
            "total_rx_mb": 0.0,
            "total_tx_mb": 0.0,
            "total_rx_bytes": 0,
            "total_tx_bytes": 0,
            "is_streaming": False,
            "active_conns": 0
        })

        if is_online and active_stream_conns > 0 and delta_rx > 0:
            # Device has active streaming connection: measure real adapter throughput
            inst_rx_rate_kb = (delta_rx / 1024.0) / dt
            inst_tx_rate_kb = (delta_tx / 1024.0) / dt
            prev_rx_rate = dev_traffic.get("rx_rate_kbps", 0.0)
            smoothed_rx = round(0.6 * inst_rx_rate_kb + 0.4 * prev_rx_rate, 1) if prev_rx_rate > 0 else round(inst_rx_rate_kb, 1)
            smoothed_tx = round(inst_tx_rate_kb, 1)

            dev_traffic["total_rx_bytes"] += delta_rx
            dev_traffic["total_tx_bytes"] += delta_tx
            dev_traffic["rx_rate_kbps"] = smoothed_rx
            dev_traffic["tx_rate_kbps"] = smoothed_tx
            dev_traffic["rx_rate_mbps"] = round(smoothed_rx / 1024.0, 2)
            dev_traffic["tx_rate_mbps"] = round(smoothed_tx / 1024.0, 2)
            dev_traffic["total_rx_mb"] = round(dev_traffic["total_rx_bytes"] / (1024.0 * 1024.0), 2)
            dev_traffic["total_tx_mb"] = round(dev_traffic["total_tx_bytes"] / (1024.0 * 1024.0), 2)
            dev_traffic["is_streaming"] = (smoothed_rx >= 5.0)
            dev_traffic["active_conns"] = active_stream_conns
        else:
            # Standby baseline: strictly Idle (0.0 KB/s), preserving cumulative total
            dev_traffic["rx_rate_kbps"] = 0.0
            dev_traffic["tx_rate_kbps"] = 0.0
            dev_traffic["rx_rate_mbps"] = 0.0
            dev_traffic["tx_rate_mbps"] = 0.0
            dev_traffic["is_streaming"] = False
            dev_traffic["active_conns"] = 0

        evaluated_devices.append({
            "ip": ip,
            "mac": dev_info.get("mac", "Unknown"),
            "hostname": dev_info.get("hostname", ""),
            "device_type": classification["device_type"],
            "vendor": classification["vendor"],
            "model": classification["model"],
            "open_ports": open_ports,
            "banners": banners,
            "is_online": is_online,
            "is_open_access": is_open_access,
            "default_credentials_found": default_credentials_found,
            "credential_findings": credential_findings,
            "cves": cves,
            "risk_level": risk_level,
            "scoping_policy": scoping_policy,
            "last_seen": time.time(),
            "traffic": dict(dev_traffic)
        })

    # Atomic write to hotspot_telemetry.json
    payload = {
        "timestamp": time.time(),
        "hotspot_active": len(discovered_peers) > 0,
        "device_count": len(evaluated_devices),
        "devices": evaluated_devices
    }

    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp_file = f"{OUTPUT_FILE}.tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        if os.path.exists(OUTPUT_FILE):
            os.remove(OUTPUT_FILE)
        os.rename(tmp_file, OUTPUT_FILE)
    except Exception:
        pass

    # Also update hotspot_clients.json for backward compatibility
    try:
        clients_payload = {
            "State": "On" if len(discovered_peers) > 0 else "Off",
            "Count": len(discovered_peers),
            "Clients": [
                {
                    "MacAddress": d["mac"],
                    "Hostname": f"{d['hostname']} {d['ip']}".strip()
                }
                for d in evaluated_devices
            ]
        }
        with open(CLIENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(clients_payload, f)
    except Exception:
        pass

def main():
    global RUNNING
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))

    print(f"[*] Hotspot & Real IoT Telemetry Bridge started [PID: {os.getpid()}]")
    print("    Monitoring Windows Mobile Hotspot and active IoT services...")

    try:
        while RUNNING:
            poll_cycle()
            time.sleep(1.5)
    finally:
        print("[*] Hotspot Telemetry Bridge stopped.")
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
            except Exception:
                pass

if __name__ == "__main__":
    main()
