#!/usr/bin/env python3
"""
Modular Camera Emulation Engine (mock-object)
Course: IT6027 - Cybersecurity Policy and Governance
Supports diverse camera profiles (D-Link, Hikvision, Dahua, IP Webcam, Open Access, Hardened)
with configurable HTTP (Basic/Digest/Open/Form), RTSP 554, UPnP SSDP, and mDNS Zeroconf.
"""

import sys
import os
import re
import json
import base64
import socket
import struct
import hashlib
import time
import uuid
import threading
from typing import Dict, Any, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Default built-in profile (D-Link DCS-932L fallback)
DEFAULT_PROFILE = {
    "profile_id": "dlink_dcs932l",
    "name": "D-Link DCS-932L IP Camera",
    "vendor": "D-Link Systems",
    "model": "DCS-932L",
    "firmware": "1.0.1",
    "serial": "DLINK932L00123",
    "default_http_port": 8080,
    "default_rtsp_port": 554,
    "http_server_banner": "GoAhead-Webs/2.5",
    "auth_type": "basic",
    "auth_realm": "D-Link DCS-932L",
    "credentials": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "123456"}
    ],
    "is_open_access": False,
    "rtsp_enabled": True,
    "rtsp_auth_type": "basic",
    "rtsp_realm": "D-Link DCS-932L",
    "ssdp_enabled": True,
    "ssdp_device_type": "urn:schemas-upnp-org:device:DigitalSecurityCamera:1",
    "ssdp_server_banner": "Linux/3.10 UPnP/1.0 GoAhead-Webs/2.5",
    "mdns_enabled": True,
    "mdns_service_name": "D-Link-DCS-932L",
    "stream_endpoints": ["/video", "/videostream.cgi", "/common/info.cgi"],
    "security_posture": "Vulnerable (Default Credentials & Outdated Firmware)"
}

def load_profile(profile_name_or_path: str) -> Dict[str, Any]:
    """Load profile by name or file path."""
    if not profile_name_or_path:
        return dict(DEFAULT_PROFILE)

    # Check direct path
    if os.path.exists(profile_name_or_path):
        with open(profile_name_or_path, "r", encoding="utf-8") as f:
            return json.load(f)

    # Check profiles directory
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    profiles_dir = os.path.abspath(os.path.join(cur_dir, "..", "profiles"))
    target = os.path.join(profiles_dir, f"{profile_name_or_path}.json")
    if os.path.exists(target):
        with open(target, "r", encoding="utf-8") as f:
            return json.load(f)

    print(f"[!] Profile '{profile_name_or_path}' not found. Using default D-Link profile.")
    return dict(DEFAULT_PROFILE)

def generate_upnp_xml(profile: Dict[str, Any]) -> str:
    """Dynamically generate UPnP device descriptor XML."""
    return f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>{profile.get("ssdp_device_type", "urn:schemas-upnp-org:device:DigitalSecurityCamera:1")}</deviceType>
    <friendlyName>{profile.get("name", "IP Camera")}</friendlyName>
    <manufacturer>{profile.get("vendor", "Generic")}</manufacturer>
    <modelDescription>{profile.get("name", "Network Surveillance Camera")}</modelDescription>
    <modelName>{profile.get("model", "IP-Cam")}</modelName>
    <modelNumber>{profile.get("firmware", "1.0.0")}</modelNumber>
    <firmwareVersion>{profile.get("firmware", "1.0.0")}</firmwareVersion>
    <serialNumber>{profile.get("serial", "CAM2026")}</serialNumber>
  </device>
</root>"""

class DynamicCameraHTTPHandler(BaseHTTPRequestHandler):
    """Profile-driven HTTP handler supporting Basic, Digest, Open Access, and Form auth."""

    server_profile: Dict[str, Any] = DEFAULT_PROFILE

    def send_camera_headers(self, status=200, content_type="text/html", extra_headers=None):
        self.send_response(status)
        banner = self.server_profile.get("http_server_banner", "GoAhead-Webs/2.5")
        self.send_header("Server", banner)
        self.send_header("Content-Type", content_type)
        self.send_header("Connection", "close")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)

    def _check_basic_auth(self) -> bool:
        auth_header = self.headers.get("Authorization", "")
        if not auth_header or not auth_header.lower().startswith("basic "):
            return False
        try:
            encoded = auth_header.split(" ", 1)[1].strip()
            decoded = base64.b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
            valid_creds = self.server_profile.get("credentials", [])
            return any(c.get("username") == username and c.get("password") == password for c in valid_creds)
        except Exception:
            return False

    def _check_digest_auth(self) -> bool:
        auth_header = self.headers.get("Authorization", "")
        if not auth_header or not auth_header.lower().startswith("digest "):
            return False
        try:
            raw_params = auth_header[7:]
            parts = re.findall(r'(\w+)=(?:"([^"]+)"|([^\s,]+))', raw_params)
            params = {p[0]: (p[1] or p[2]) for p in parts}

            user = params.get("username", "")
            realm = params.get("realm", self.server_profile.get("auth_realm", "IPCamera"))
            nonce = params.get("nonce", "")
            uri = params.get("uri", "/")
            response = params.get("response", "")
            qop = params.get("qop", "")
            nc = params.get("nc", "")
            cnonce = params.get("cnonce", "")

            valid_creds = self.server_profile.get("credentials", [])
            matched = [c for c in valid_creds if c.get("username") == user]
            if not matched:
                return False

            for c in matched:
                pwd = c.get("password", "")
                ha1 = hashlib.md5(f"{user}:{realm}:{pwd}".encode()).hexdigest()
                ha2 = hashlib.md5(f"{self.command}:{uri}".encode()).hexdigest()
                if qop:
                    expected = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
                else:
                    expected = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
                if expected.lower() == response.lower():
                    return True
            return False
        except Exception:
            return False

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # UPnP XML descriptor
        if path in ["/desc.xml", "/setup.xml"]:
            xml_data = generate_upnp_xml(self.server_profile)
            self.send_camera_headers(200, "text/xml")
            self.end_headers()
            self.wfile.write(xml_data.encode("utf-8"))
            return

        auth_type = self.server_profile.get("auth_type", "basic").lower()
        is_open = self.server_profile.get("is_open_access", False)

        # 1. Unauthenticated Open Access
        if is_open or auth_type == "none":
            self.send_camera_headers(200, "text/html")
            body = (
                f"<html><head><title>{self.server_profile.get('name')} - Live Stream</title></head>"
                f"<body><h1>{self.server_profile.get('name')}</h1>"
                f"<p>Status: Online | Live Camera Stream</p>"
                f"<div class='feed'><p>Video Stream Active: /videostream.cgi</p></div>"
                f"</body></html>"
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return

        # 2. HTTP Basic Authentication
        if auth_type == "basic":
            if not self._check_basic_auth():
                realm = self.server_profile.get("auth_realm", "IP Camera")
                self.send_response(401)
                self.send_header("Server", self.server_profile.get("http_server_banner", "GoAhead-Webs/2.5"))
                self.send_header("WWW-Authenticate", f'Basic realm="{realm}"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

        # 3. HTTP Digest Authentication (Android IP Webcam / Modern Cameras)
        elif auth_type == "digest":
            if not self._check_digest_auth():
                realm = self.server_profile.get("auth_realm", "IP Camera")
                nonce = uuid.uuid4().hex[:16]
                self.send_response(401)
                self.send_header("Server", self.server_profile.get("http_server_banner", "IP Webcam Server/1.14"))
                self.send_header("WWW-Authenticate", f'Digest realm="{realm}", nonce="{nonce}", qop="auth"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

        # Authenticated view
        self.send_camera_headers(200, "text/html")
        body = (
            f"<html><head><title>{self.server_profile.get('name')} Administration</title></head>"
            f"<body><h1>{self.server_profile.get('name')} Live Stream</h1>"
            f"<p>Model: {self.server_profile.get('model')} | Firmware: {self.server_profile.get('firmware')}</p>"
            f"<p>Authenticated Session Active</p></body></html>"
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        return

class DynamicCameraRTSPServer:
    """RTSP server handling OPTIONS and DESCRIBE with Basic, Digest, or Open access."""

    def __init__(self, port: int, profile: Dict[str, Any], ip: str = "0.0.0.0"):
        self.port = port
        self.profile = profile
        self.ip = ip or "0.0.0.0"
        self.running = False
        self.sock: Optional[socket.socket] = None

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.ip, self.port))
            self.sock.listen(10)
            self.running = True
            threading.Thread(target=self._listen_loop, daemon=True).start()
            print(f"[+] RTSP Server active on {self.ip}:{self.port} (Auth: {self.profile.get('rtsp_auth_type')})")
        except PermissionError:
            print(f"[!] Warning: Port {self.port} requires root/administrator privileges. RTSP disabled.")
        except Exception as e:
            print(f"[!] RTSP Server bind error on port {self.port}: {e}")

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    def _listen_loop(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
            except Exception:
                break

    def _handle_client(self, conn: socket.socket, addr):
        conn.settimeout(3.0)
        auth_type = self.profile.get("rtsp_auth_type", "basic").lower()
        realm = self.profile.get("rtsp_realm", self.profile.get("name", "IPCamera"))
        banner = self.profile.get("http_server_banner", "GoAhead-Webs/2.5")

        try:
            while self.running:
                data = conn.recv(2048).decode("utf-8", errors="ignore")
                if not data:
                    break

                lines = data.split("\r\n")
                first_line = lines[0] if lines else ""
                cseq = "1"
                auth_header = None
                for line in lines:
                    if line.lower().startswith("cseq:"):
                        cseq = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("authorization:"):
                        auth_header = line.split(":", 1)[1].strip()

                if "OPTIONS" in first_line:
                    resp = (
                        f"RTSP/1.0 200 OK\r\n"
                        f"CSeq: {cseq}\r\n"
                        f"Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n"
                        f"Server: {banner}\r\n\r\n"
                    )
                    conn.sendall(resp.encode("utf-8"))

                elif "DESCRIBE" in first_line:
                    # Check authentication
                    is_authed = False
                    if auth_type == "none" or self.profile.get("is_open_access"):
                        is_authed = True
                    elif auth_type == "basic" and auth_header and "basic" in auth_header.lower():
                        try:
                            token = auth_header.split(" ", 1)[1].strip()
                            dec = base64.b64decode(token).decode("utf-8")
                            u, p = dec.split(":", 1)
                            is_authed = any(c.get("username") == u and c.get("password") == p for c in self.profile.get("credentials", []))
                        except Exception:
                            pass
                    elif auth_type == "digest" and auth_header and "digest" in auth_header.lower():
                        # Basic Digest token match
                        try:
                            parts = re.findall(r'(\w+)=(?:"([^"]+)"|([^\s,]+))', auth_header)
                            params = {p[0]: (p[1] or p[2]) for p in parts}
                            u = params.get("username", "")
                            is_authed = any(c.get("username") == u for c in self.profile.get("credentials", []))
                        except Exception:
                            pass

                    if is_authed:
                        resp = (
                            f"RTSP/1.0 200 OK\r\n"
                            f"CSeq: {cseq}\r\n"
                            f"Content-Type: application/sdp\r\n"
                            f"Server: {banner}\r\n\r\n"
                        )
                    else:
                        challenge = f'Basic realm="{realm}"' if auth_type != "digest" else f'Digest realm="{realm}", nonce="d8a9e2026"'
                        resp = (
                            f"RTSP/1.0 401 Unauthorized\r\n"
                            f"CSeq: {cseq}\r\n"
                            f"WWW-Authenticate: {challenge}\r\n"
                            f"Server: {banner}\r\n\r\n"
                        )
                    conn.sendall(resp.encode("utf-8"))
                else:
                    break
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

class DynamicSSDPResponder:
    """Robust UPnP SSDP responder with 64-bit struct packing fix and dynamic IP probe."""

    def __init__(self, http_port: int, profile: Dict[str, Any], explicit_ip: Optional[str] = None):
        self.http_port = http_port
        self.profile = profile
        self.explicit_ip = explicit_ip or os.environ.get("MOCK_IP")
        self.running = False
        self.sock: Optional[socket.socket] = None

    def start(self):
        if not self.profile.get("ssdp_enabled", True):
            return
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("", 1900))

            # Fix MO-01: Portable 8-byte format '=4sl' or '4s4s'
            mreq = struct.pack("4s4s", socket.inet_aton("239.255.255.250"), socket.inet_aton("0.0.0.0"))
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self.running = True
            threading.Thread(target=self._loop, daemon=True).start()
            print(f"[+] SSDP Responder active on UDP 1900 for {self.profile.get('name')}")
        except Exception as e:
            print(f"[!] SSDP Responder setup warning: {e}")

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    def _loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                msg = data.decode("utf-8", errors="ignore")
                if "M-SEARCH" in msg:
                    # Fix MO-03: Dynamic IP route probe towards requester
                    my_ip = self.explicit_ip
                    if not my_ip:
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            s.connect((addr[0], addr[1] or 80))
                            my_ip = s.getsockname()[0]
                            s.close()
                        except Exception:
                            my_ip = socket.gethostbyname(socket.gethostname())

                    dev_type = self.profile.get("ssdp_device_type", "urn:schemas-upnp-org:device:DigitalSecurityCamera:1")
                    server_str = self.profile.get("ssdp_server_banner", "Linux/3.10 UPnP/1.0 GoAhead-Webs/2.5")
                    usn = f"uuid:{self.profile.get('profile_id', 'camera')}-00123::{dev_type}"

                    response = (
                        "HTTP/1.1 200 OK\r\n"
                        "CACHE-CONTROL: max-age=1800\r\n"
                        "EXT:\r\n"
                        f"LOCATION: http://{my_ip}:{self.http_port}/desc.xml\r\n"
                        f"SERVER: {server_str}\r\n"
                        f"ST: {dev_type}\r\n"
                        f"USN: {usn}\r\n\r\n"
                    )
                    self.sock.sendto(response.encode("utf-8"), addr)
            except Exception:
                break

class DynamicMDNSAdvertiser:
    """Registers mDNS Zeroconf advertisement for camera."""

    def __init__(self, http_port: int, profile: Dict[str, Any], explicit_ip: Optional[str] = None):
        self.http_port = http_port
        self.profile = profile
        self.explicit_ip = explicit_ip or os.environ.get("MOCK_IP")
        self.zc = None
        self.info = None

    def start(self):
        if not self.profile.get("mdns_enabled", True):
            return
        try:
            from zeroconf import Zeroconf, ServiceInfo
            self.zc = Zeroconf()

            host_ip = self.explicit_ip or socket.gethostbyname(socket.gethostname())
            ip_bytes = socket.inet_aton(host_ip)

            svc_name = self.profile.get("mdns_service_name", "Mock-Camera")
            self.info = ServiceInfo(
                "_camera._tcp.local.",
                f"{svc_name}._camera._tcp.local.",
                addresses=[ip_bytes],
                port=self.http_port,
                properties={
                    "model": self.profile.get("model", "Camera"),
                    "vendor": self.profile.get("vendor", "Generic"),
                    "firmware": self.profile.get("firmware", "1.0.0")
                },
                server=f"{self.profile.get('profile_id', 'camera')}.local."
            )
            self.zc.register_service(self.info)
            print(f"[+] mDNS Advertiser registered: {svc_name}._camera._tcp.local.")
        except ImportError:
            print("[i] Note: zeroconf package not installed; mDNS advertising skipped.")
        except Exception as e:
            print(f"[!] mDNS Advertiser warning: {e}")

    def stop(self):
        if self.zc and self.info:
            try:
                self.zc.unregister_service(self.info)
                self.zc.close()
            except Exception:
                pass

class CameraServer:
    """Complete camera server orchestrator managing HTTP, RTSP, SSDP, and mDNS services."""

    def __init__(self, profile_name_or_dict: Any = "dlink_dcs932l",
                 http_port: Optional[int] = None,
                 rtsp_port: Optional[int] = None,
                 ip: Optional[str] = None):
        if isinstance(profile_name_or_dict, dict):
            self.profile = dict(profile_name_or_dict)
        else:
            self.profile = load_profile(profile_name_or_dict)

        self.http_port = http_port or self.profile.get("default_http_port", 8080)
        self.rtsp_port = rtsp_port or self.profile.get("default_rtsp_port", 554)
        self.ip = ip or os.environ.get("MOCK_IP", "0.0.0.0")
        self.http_server: Optional[HTTPServer] = None
        self.rtsp_server: Optional[DynamicCameraRTSPServer] = None
        self.ssdp_responder: Optional[DynamicSSDPResponder] = None
        self.mdns_advertiser: Optional[DynamicMDNSAdvertiser] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, blocking: bool = False):
        print("=" * 65)
        print(f"      Mock IoT Camera - {self.profile.get('name')}")
        print("=" * 65)
        print(f"  Brand/Model:  {self.profile.get('vendor')} {self.profile.get('model')}")
        print(f"  Firmware:     {self.profile.get('firmware')}")
        print(f"  Posture:      {self.profile.get('security_posture')}")
        print(f"  HTTP Port:    {self.http_port} (Auth: {self.profile.get('auth_type')})")
        print(f"  RTSP Port:    {self.rtsp_port}")
        print("-" * 65)

        # 1. Start RTSP
        if self.profile.get("rtsp_enabled", True):
            self.rtsp_server = DynamicCameraRTSPServer(self.rtsp_port, self.profile, ip=self.ip)
            self.rtsp_server.start()

        # 2. Start SSDP
        if self.profile.get("ssdp_enabled", True):
            self.ssdp_responder = DynamicSSDPResponder(self.http_port, self.profile, explicit_ip=self.ip if self.ip != "0.0.0.0" else None)
            self.ssdp_responder.start()

        # 3. Start mDNS
        if self.profile.get("mdns_enabled", True):
            self.mdns_advertiser = DynamicMDNSAdvertiser(self.http_port, self.profile, explicit_ip=self.ip if self.ip != "0.0.0.0" else None)
            self.mdns_advertiser.start()

        # 4. Start HTTP Server
        handler_cls = type(f"Handler_{self.profile.get('profile_id')}", (DynamicCameraHTTPHandler,), {
            "server_profile": self.profile
        })
        self.http_server = HTTPServer((self.ip, self.http_port), handler_cls)
        print(f"[+] HTTP Server listening on http://{self.ip}:{self.http_port}")

        if blocking:
            try:
                self.http_server.serve_forever()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
            self._thread.start()

    def stop(self):
        print(f"[*] Stopping Mock Camera ({self.profile.get('name')})...")
        if self.http_server:
            try:
                # Run shutdown in a background thread to unblock serve_forever
                threading.Thread(target=self.http_server.shutdown, daemon=True).start()
                time.sleep(0.05)
                self.http_server.server_close()
            except Exception:
                pass
        if self.rtsp_server:
            self.rtsp_server.stop()
        if self.ssdp_responder:
            self.ssdp_responder.stop()
        if self.mdns_advertiser:
            self.mdns_advertiser.stop()
        print("[+] Mock Camera stopped.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Modular Mock Camera Server (mock-object)")
    parser.add_argument("--profile", type=str, default="dlink_dcs932l", help="Profile name (dlink_dcs932l, hikvision_ds2cd, dahua_ipc, ip_webcam, open_access_cam, hardened_cam) or path")
    parser.add_argument("--port", "--http-port", dest="http_port", type=int, default=None, help="HTTP server port")
    parser.add_argument("--rtsp-port", type=int, default=None, help="RTSP server port")
    parser.add_argument("--ip", type=str, default="0.0.0.0", help="IP address to bind")
    parser.add_argument("--auth-type", type=str, default=None, choices=["basic", "digest", "none", "form"], help="Override authentication type")
    parser.add_argument("--open-access", action="store_true", help="Force unauthenticated open access")

    args = parser.parse_args()

    prof = load_profile(args.profile)
    if args.auth_type:
        prof["auth_type"] = args.auth_type
    if args.open_access:
        prof["is_open_access"] = True
        prof["auth_type"] = "none"
        prof["rtsp_auth_type"] = "none"

    server = CameraServer(profile_name_or_dict=prof, http_port=args.http_port, rtsp_port=args.rtsp_port, ip=args.ip)
    server.start(blocking=True)
