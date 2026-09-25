#!/usr/bin/env python3
"""
Simulated Legacy IP Camera (mock-object template)
Emulates a D-Link DCS-932L IP Camera with:
- HTTP Basic Auth (default creds: admin:admin)
- Vulnerable server header: GoAhead-Webs/2.5 (CVE-2020-25078)
- UPnP SSDP device XML endpoint
- mDNS advertisement
"""

import sys
import base64
import socket
import struct
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

UPNP_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:DigitalSecurityCamera:1</deviceType>
    <friendlyName>D-Link DCS-932L IP Camera</friendlyName>
    <manufacturer>D-Link Systems</manufacturer>
    <modelDescription>Wireless N Day & Night Home Network Camera</modelDescription>
    <modelName>DCS-932L</modelName>
    <modelNumber>1.0.1</modelNumber>
    <firmwareVersion>1.0.1</firmwareVersion>
    <serialNumber>DLINK932L00123</serialNumber>
  </device>
</root>"""

class CameraHTTPHandler(BaseHTTPRequestHandler):
    def send_camera_headers(self, status=200, content_type="text/html"):
        self.send_response(status)
        self.send_header("Server", "GoAhead-Webs/2.5")
        self.send_header("Content-Type", content_type)
        self.send_header("Connection", "close")

    def check_auth(self):
        auth_header = self.headers.get("Authorization")
        if not auth_header:
            return False
        try:
            auth_type, encoded = auth_header.split(" ", 1)
            if auth_type.lower() != "basic":
                return False
            decoded = base64.b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
            # Vulnerable default credentials
            return (username == "admin" and password in ["admin", "123456", "password"])
        except Exception:
            return False

    def do_GET(self):
        if self.path == "/desc.xml":
            self.send_camera_headers(200, "text/xml")
            self.end_headers()
            self.wfile.write(UPNP_XML.encode("utf-8"))
            return

        if not self.check_auth():
            self.send_response(401)
            self.send_header("Server", "GoAhead-Webs/2.5")
            self.send_header("WWW-Authenticate", 'Basic realm="D-Link DCS-932L"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self.send_camera_headers(200, "text/html")
        body = "<html><body><h1>D-Link DCS-932L Live Camera Stream</h1><p>Status: Online</p></body></html>"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        return

def run_ssdp_responder(http_port=8080):
    """Answers UPnP SSDP M-SEARCH requests."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 1900))
        mreq = struct.pack("4sl", socket.inet_aton("239.255.255.250"), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        while True:
            data, addr = sock.recvfrom(2048)
            msg = data.decode("utf-8", errors="ignore")
            if "M-SEARCH" in msg:
                my_ip = socket.gethostbyname(socket.gethostname())
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "CACHE-CONTROL: max-age=1800\r\n"
                    "EXT:\r\n"
                    f"LOCATION: http://{my_ip}:{http_port}/desc.xml\r\n"
                    "SERVER: Linux/3.10 UPnP/1.0 GoAhead-Webs/2.5\r\n"
                    "ST: urn:schemas-upnp-org:device:DigitalSecurityCamera:1\r\n"
                    "USN: uuid:dlink-dcs-932l-00123::urn:schemas-upnp-org:device:DigitalSecurityCamera:1\r\n\r\n"
                )
                sock.sendto(response.encode("utf-8"), addr)
    except Exception:
        pass

def handle_rtsp_client(conn, addr):
    try:
        data = conn.recv(2048).decode("utf-8", errors="ignore")
        if "OPTIONS" in data:
            cseq = "1"
            for line in data.split("\r\n"):
                if line.lower().startswith("cseq:"):
                    cseq = line.split(":", 1)[1].strip()
            resp = (
                f"RTSP/1.0 200 OK\r\n"
                f"CSeq: {cseq}\r\n"
                f"Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n"
                f"Server: GoAhead-Webs/2.5\r\n\r\n"
            )
            conn.sendall(resp.encode("utf-8"))
        elif "DESCRIBE" in data:
            cseq = "1"
            auth_header = None
            for line in data.split("\r\n"):
                if line.lower().startswith("cseq:"):
                    cseq = line.split(":", 1)[1].strip()
                elif line.lower().startswith("authorization:"):
                    auth_header = line.split(":", 1)[1].strip()

            auth_valid = False
            if auth_header and "basic" in auth_header.lower():
                try:
                    token = auth_header.split(" ", 1)[1].strip()
                    dec = base64.b64decode(token).decode("utf-8")
                    u, p = dec.split(":", 1)
                    if u == "admin" and p in ["admin", "123456", "password"]:
                        auth_valid = True
                except Exception:
                    pass

            if auth_valid:
                resp = (
                    f"RTSP/1.0 200 OK\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Content-Type: application/sdp\r\n"
                    f"Server: GoAhead-Webs/2.5\r\n\r\n"
                )
            else:
                resp = (
                    f"RTSP/1.0 401 Unauthorized\r\n"
                    f"CSeq: {cseq}\r\n"
                    f'WWW-Authenticate: Basic realm="D-Link DCS-932L"\r\n'
                    f"Server: GoAhead-Webs/2.5\r\n\r\n"
                )
            conn.sendall(resp.encode("utf-8"))
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

def run_rtsp_server(port=554):
    """Answers RTSP OPTIONS and DESCRIBE requests on port 554."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(10)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_rtsp_client, args=(conn, addr), daemon=True).start()
    except Exception:
        pass

def run_mdns_advertiser(http_port=8080):
    try:
        from zeroconf import Zeroconf, ServiceInfo
        zc = Zeroconf()
        ip_bytes = socket.inet_aton(socket.gethostbyname(socket.gethostname()))
        info = ServiceInfo(
            "_camera._tcp.local.",
            "D-Link-DCS-932L._camera._tcp.local.",
            addresses=[ip_bytes],
            port=http_port,
            properties={"model": "DCS-932L", "vendor": "D-Link"},
            server="dlink-cam.local."
        )
        zc.register_service(info)
    except Exception:
        pass

if __name__ == "__main__":
    port = 8080
    threading.Thread(target=run_ssdp_responder, args=(port,), daemon=True).start()
    threading.Thread(target=run_rtsp_server, args=(554,), daemon=True).start()
    threading.Thread(target=run_mdns_advertiser, args=(port,), daemon=True).start()
    server = HTTPServer(("0.0.0.0", port), CameraHTTPHandler)
    print(f"[*] Mock Camera online on HTTP port {port} and RTSP port 554")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
