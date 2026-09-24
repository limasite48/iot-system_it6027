#!/usr/bin/env python3
"""
Simulated Smart Plug (mock-object template)
Emulates a TP-Link / Belkin WeMo Smart Plug with:
- Unauthenticated HTTP JSON Control API (CVE-2019-14923 simulation)
- UPnP SSDP discovery responder
- Open relay control endpoint
"""

import sys
import json
import socket
import struct
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

PLUG_STATE = {"state": "ON", "voltage": 220.4, "current": 0.42, "model": "HS100", "vendor": "TP-Link", "firmware": "1.1.0"}

UPNP_XML = """<?xml version="1.0"?>
<root xmlns="urn:Belkin:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:Belkin:device:controllee:1</deviceType>
    <friendlyName>Living Room Smart Plug</friendlyName>
    <manufacturer>Belkin International Inc.</manufacturer>
    <modelDescription>Belkin Smart Switch</modelDescription>
    <modelName>WeMo Switch</modelName>
    <modelNumber>1.0</modelNumber>
    <firmwareVersion>WeMo_WW_2.00.11057</firmwareVersion>
    <serialNumber>WEMO99887766</serialNumber>
  </device>
</root>"""

class SmartPlugHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/setup.xml" or self.path == "/desc.xml":
            self.send_response(200)
            self.send_header("Server", "Unspecified, UPnP/1.0, Portable SDK for UPnP devices/1.6.6")
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(UPNP_XML.encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Server", "TP-LINK Smart Plug HTTP Server 1.0")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(PLUG_STATE, indent=2).encode("utf-8"))

    def do_POST(self):
        # Open control endpoint without authentication
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
        if "toggle" in body.lower() or "off" in body.lower():
            PLUG_STATE["state"] = "OFF" if PLUG_STATE["state"] == "ON" else "ON"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"success": True, "new_state": PLUG_STATE["state"]}).encode("utf-8"))

    def log_message(self, format, *args):
        return

def run_ssdp_responder(http_port=80):
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
                    f"LOCATION: http://{my_ip}:{http_port}/setup.xml\r\n"
                    "SERVER: Unspecified, UPnP/1.0, Portable SDK for UPnP devices/1.6.6\r\n"
                    "ST: urn:Belkin:device:controllee:1\r\n"
                    "USN: uuid:Socket-1_0-221443K0101859::urn:Belkin:device:controllee:1\r\n\r\n"
                )
                sock.sendto(response.encode("utf-8"), addr)
    except Exception:
        pass

if __name__ == "__main__":
    port = 80
    threading.Thread(target=run_ssdp_responder, args=(port,), daemon=True).start()
    server = HTTPServer(("0.0.0.0", port), SmartPlugHTTPHandler)
    print(f"[*] Mock SmartPlug online on port {port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
