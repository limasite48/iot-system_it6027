import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest

from app.audit.credential_checker import load_default_credentials, test_device_credentials as audit_device_credentials

def test_load_default_credentials():
    creds = load_default_credentials()
    assert len(creds) >= 15
    pairs = set(creds)
    assert ("admin", "admin") in pairs
    assert ("admin", "123456") in pairs
    assert ("root", "xc3511") in pairs  # Mirai default
    assert ("root", "root") in pairs

class MultiAuthHandler(BaseHTTPRequestHandler):
    mode = "open"

    def do_GET(self):
        if self.mode == "open":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>IP Webcam</title></head><body><h1>Streaming</h1></body></html>")
            return

        if self.mode == "digest_admin":
            auth_header = self.headers.get("Authorization", "")
            if not auth_header:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Digest realm="IPWebcam", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", qop="auth"')
                self.end_headers()
                self.wfile.write(b"401 Unauthorized")
                return
            if "admin" in auth_header and "Digest" in auth_header:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Authorized Stream")
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Digest realm="IPWebcam", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", qop="auth"')
                self.end_headers()
                self.wfile.write(b"401 Unauthorized")
            return

        if self.mode == "basic_admin":
            auth_header = self.headers.get("Authorization", "")
            if auth_header == "Basic YWRtaW46YWRtaW4=": # admin:admin
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Authorized")
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="TestCamera"')
                self.end_headers()
                self.wfile.write(b"401 Unauthorized")
            return

        if self.mode == "strong_pass":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Digest realm="SecureDevice", nonce="999", qop="auth"')
            self.end_headers()
            self.wfile.write(b"401 Unauthorized")
            return

    def log_message(self, format, *args):
        return

@pytest.fixture(scope="module")
def multi_auth_server():
    server = HTTPServer(("127.0.0.1", 18888), MultiAuthHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)
    yield 18888
    server.shutdown()
    server.server_close()

def test_no_password_open_access_detection(multi_auth_server):
    port = multi_auth_server
    MultiAuthHandler.mode = "open"
    res = audit_device_credentials("127.0.0.1", [port])
    assert res["vulnerable"] is True
    assert len(res["findings"]) == 1
    finding = res["findings"][0]
    assert finding["is_open_access"] is True
    assert "No Password" in finding["credential"]

def test_digest_auth_admin_admin_detection(multi_auth_server):
    port = multi_auth_server
    MultiAuthHandler.mode = "digest_admin"
    res = audit_device_credentials("127.0.0.1", [port])
    assert res["vulnerable"] is True
    assert len(res["findings"]) == 1
    finding = res["findings"][0]
    assert finding["is_open_access"] is False
    assert finding["credential"] == "admin:admin"
    assert "Digest" in finding["service"]

def test_basic_auth_admin_admin_detection(multi_auth_server):
    port = multi_auth_server
    MultiAuthHandler.mode = "basic_admin"
    res = audit_device_credentials("127.0.0.1", [port])
    assert res["vulnerable"] is True
    assert len(res["findings"]) == 1
    finding = res["findings"][0]
    assert finding["is_open_access"] is False
    assert finding["credential"] == "admin:admin"
    assert "Basic" in finding["service"]

def test_strong_password_not_flagged(multi_auth_server):
    port = multi_auth_server
    MultiAuthHandler.mode = "strong_pass"
    res = audit_device_credentials("127.0.0.1", [port])
    assert res["vulnerable"] is False
    assert len(res["findings"]) == 0
