import asyncio
import threading
import time
import importlib.util
import os
import pytest
from app.scanner_engine import SecurityScannerEngine

@pytest.fixture(scope="module")
def mock_camera_service():
    """Start mock camera HTTP server on loopback port 8088 for test duration."""
    cam_script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "mock-object", "templates", "camera-mock", "camera_server.py"))
    spec = importlib.util.spec_from_file_location("mock_cam", cam_script)
    mock_cam = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mock_cam)

    test_port = 8080
    server = mock_cam.HTTPServer(("127.0.0.1", test_port), mock_cam.CameraHTTPHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)
    yield test_port
    server.server_close()

def test_full_device_audit_pipeline(mock_camera_service):
    port = mock_camera_service
    engine = SecurityScannerEngine()

    # Deep scan single device on 127.0.0.1 specifying port
    device = asyncio.run(engine.scan_single_device(
        ip="127.0.0.1",
        mac="00:0F:7D:AA:BB:CC"  # D-Link OUI
    ))

    # Assertions on mandatory project requirements
    assert device["device_type"] == "IP Camera"
    assert "D-Link" in device["vendor"]
    assert device["default_credentials_found"] is True
    assert any(f["credential"] == "admin:admin" for f in device["credential_findings"])
    assert any(c["cve_id"] == "CVE-2020-25078" for c in device["cves"])

    # Assertions on bonus requirements (VLAN Scoping & Alerts)
    assert device["scoping_policy"]["quarantine_required"] is True
    assert "Quarantine" in device["scoping_policy"]["recommended_vlan"]
    assert len(engine.alerts) >= 1
