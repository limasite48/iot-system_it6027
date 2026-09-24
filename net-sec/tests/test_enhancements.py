import asyncio
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest

from app.audit.credential_checker import test_device_credentials as audit_device_credentials, load_default_credentials
from app.monitoring.traffic_meter import TrafficMeter, GLOBAL_TRAFFIC_METER
from app.scanner_engine import SecurityScannerEngine

class OpenWebcamHandler(BaseHTTPRequestHandler):
    """Simulates an IP Webcam with NO password configured (open 200 OK stream)."""
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><head><title>IP Webcam</title></head><body><h1>Live Video Feed</h1></body></html>")

    def log_message(self, format, *args):
        return

@pytest.fixture(scope="module")
def open_webcam_server():
    server = HTTPServer(("127.0.0.1", 8089), OpenWebcamHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    yield 8089
    server.shutdown()
    server.server_close()

def test_open_access_no_password_detected(open_webcam_server):
    port = open_webcam_server
    # Test credential checker against open endpoint
    result = audit_device_credentials("127.0.0.1", [port])
    
    assert result["vulnerable"] is True
    assert len(result["findings"]) >= 1
    finding = result["findings"][0]
    assert finding["is_open_access"] is True
    assert "Open Access" in finding["credential"] or "No Password" in finding["credential"]

def test_traffic_meter_snapshot():
    meter = TrafficMeter(target_subnet_prefix="192.168.137.")
    snap = meter.get_snapshot()
    assert "interface" in snap
    assert "total_rx_mb" in snap
    assert "total_tx_mb" in snap
    assert "rx_rate_kbps" in snap
    assert isinstance(snap["total_rx_bytes"], (int, float))

def test_presence_monitor_online_state():
    engine = SecurityScannerEngine()
    # 127.0.0.1 should be alive
    alive = engine.check_host_alive("127.0.0.1")
    assert alive is True
