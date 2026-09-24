#!/usr/bin/env python3
"""
Simulated DVR Gateway (mock-object template)
Emulates an embedded DVR/Router susceptible to Mirai:
- Telnet on port 23 (BusyBox v1.1.2 banner, default creds root:xc3511)
- HTTP on port 80 (CVE-2017-8225 / Xiongmai web server banner)
"""

import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

TELNET_PORT = 23
HTTP_PORT = 80

def handle_telnet_client(conn, addr):
    try:
        conn.sendall(b"\r\n\r\nBusyBox v1.1.2 (2014-06-12 11:20:10 CST) Built-in shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n\r\nlogin: ")
        user = conn.recv(1024).decode("utf-8", errors="ignore").strip()
        conn.sendall(b"Password: ")
        passwd = conn.recv(1024).decode("utf-8", errors="ignore").strip()

        # Mirai hardcoded credentials
        if (user == "root" and passwd == "xc3511") or (user == "admin" and passwd == "admin"):
            conn.sendall(b"\r\n# Welcome to Embedded Linux DVR shell.\r\n# ")
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                cmd = data.decode("utf-8", errors="ignore").strip()
                if cmd in ["exit", "quit"]:
                    break
                conn.sendall(b"\r\nCommand executed.\r\n# ")
        else:
            conn.sendall(b"\r\nLogin incorrect\r\n")
    except Exception:
        pass
    finally:
        conn.close()

def run_telnet_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", TELNET_PORT))
        server.listen(10)
        print(f"[*] Mock DVR Telnet listening on port {TELNET_PORT}")
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_telnet_client, args=(conn, addr), daemon=True).start()
    except Exception as e:
        print(f"[!] Telnet server error: {e}")

class DVRWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "uc-httpd 1.0.0 (Xiongmai DVR)")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        body = "<html><head><title>H.264 DVR Login</title></head><body><h2>NET Surveillance System</h2></body></html>"
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    threading.Thread(target=run_telnet_server, daemon=True).start()
    web_server = HTTPServer(("0.0.0.0", HTTP_PORT), DVRWebHandler)
    print(f"[*] Mock DVR WebUI listening on port {HTTP_PORT}")
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        web_server.server_close()
