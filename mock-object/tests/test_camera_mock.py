import os
import sys
import time
import socket
import pytest
import httpx

# Ensure mock-object engine and fleet manager are importable
CUR_DIR = os.path.dirname(os.path.abspath(__file__))
MOCK_OBJ_DIR = os.path.abspath(os.path.join(CUR_DIR, ".."))
ENGINE_DIR = os.path.join(MOCK_OBJ_DIR, "engine")

if MOCK_OBJ_DIR not in sys.path:
    sys.path.insert(0, MOCK_OBJ_DIR)
if ENGINE_DIR not in sys.path:
    sys.path.insert(0, ENGINE_DIR)

from camera_server import CameraServer, load_profile, generate_upnp_xml
from fleet_manager import get_available_profiles_info, AVAILABLE_PROFILES

def test_load_all_profiles():
    """Verify all 6 built-in camera profiles load cleanly with required fields."""
    profiles = ["dlink_dcs932l", "hikvision_ds2cd", "dahua_ipc", "ip_webcam", "open_access_cam", "hardened_cam"]
    for p_name in profiles:
        prof = load_profile(p_name)
        assert prof["profile_id"] == p_name
        assert "vendor" in prof
        assert "model" in prof
        assert "default_http_port" in prof
        assert "auth_type" in prof
        assert "http_server_banner" in prof

def test_upnp_xml_generation():
    """Verify UPnP XML descriptor generation for D-Link and Hikvision."""
    dlink_prof = load_profile("dlink_dcs932l")
    xml_out = generate_upnp_xml(dlink_prof)
    assert "<friendlyName>D-Link DCS-932L IP Camera</friendlyName>" in xml_out
    assert "<manufacturer>D-Link Systems</manufacturer>" in xml_out
    assert "<modelName>DCS-932L</modelName>" in xml_out

    hik_prof = load_profile("hikvision_ds2cd")
    hik_xml = generate_upnp_xml(hik_prof)
    assert "<friendlyName>Hikvision DS-2CD Network Camera</friendlyName>" in hik_xml
    assert "<manufacturer>Hikvision</manufacturer>" in hik_xml

def test_dlink_camera_http_basic_auth():
    """Verify D-Link camera HTTP server challenges for Basic auth and accepts default credentials."""
    port = 18080
    server = CameraServer(profile_name_or_dict="dlink_dcs932l", http_port=port, ip="127.0.0.1")
    server.start(blocking=False)
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{port}/"
        with httpx.Client(timeout=2.0) as client:
            # 1. Unauthenticated request should yield 401
            resp = client.get(url)
            assert resp.status_code == 401
            assert "Basic" in resp.headers.get("WWW-Authenticate", "")
            assert "GoAhead-Webs/2.5" in resp.headers.get("Server", "")

            # 2. Authenticated request with admin:admin should yield 200 OK
            auth_resp = client.get(url, auth=("admin", "admin"))
            assert auth_resp.status_code == 200
            assert "Live Stream" in auth_resp.text

            # 3. Invalid credentials should yield 401
            bad_auth = client.get(url, auth=("admin", "wrong_pass_999"))
            assert bad_auth.status_code == 401

            # 4. UPnP XML endpoint
            xml_resp = client.get(f"http://127.0.0.1:{port}/desc.xml")
            assert xml_resp.status_code == 200
            assert "DCS-932L" in xml_resp.text
    finally:
        server.stop()

def test_open_access_camera_no_password_required():
    """Verify open access camera grants video stream without credentials (ETSI EN 303 645 violation)."""
    port = 18081
    server = CameraServer(profile_name_or_dict="open_access_cam", http_port=port, ip="127.0.0.1")
    server.start(blocking=False)
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{port}/"
        with httpx.Client(timeout=2.0) as client:
            resp = client.get(url)
            assert resp.status_code == 200
            assert "Live Camera Stream" in resp.text
            assert "/videostream.cgi" in resp.text
            assert "OpenStream" in resp.headers.get("Server", "")
    finally:
        server.stop()

def test_hikvision_camera_digest_auth():
    """Verify Hikvision camera challenges with Digest auth and accepts admin:admin."""
    port = 18082
    server = CameraServer(profile_name_or_dict="hikvision_ds2cd", http_port=port, ip="127.0.0.1")
    server.start(blocking=False)
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{port}/"
        with httpx.Client(timeout=2.0) as client:
            # 1. Unauthenticated yields 401 Digest challenge
            resp = client.get(url)
            assert resp.status_code == 401
            assert "Digest" in resp.headers.get("WWW-Authenticate", "")
            assert "App-webs" in resp.headers.get("Server", "")

            # 2. Authenticated with DigestAuth
            auth_resp = client.get(url, auth=httpx.DigestAuth("admin", "admin"))
            assert auth_resp.status_code == 200
            assert "Live Stream" in auth_resp.text
    finally:
        server.stop()

def test_camera_rtsp_options_and_describe():
    """Verify camera RTSP server handles OPTIONS and DESCRIBE commands."""
    rtsp_p = 18554
    http_p = 18083
    server = CameraServer(profile_name_or_dict="dlink_dcs932l", http_port=http_p, rtsp_port=rtsp_p, ip="127.0.0.1")
    server.start(blocking=False)
    time.sleep(0.3)

    try:
        # Test RTSP OPTIONS
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("127.0.0.1", rtsp_p))
        s.sendall(b"OPTIONS rtsp://127.0.0.1:18554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        data = s.recv(1024).decode("utf-8", errors="ignore")
        assert "RTSP/1.0 200 OK" in data
        assert "Public:" in data
        s.close()

        # Test RTSP DESCRIBE without auth
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(2.0)
        s2.connect(("127.0.0.1", rtsp_p))
        s2.sendall(b"DESCRIBE rtsp://127.0.0.1:18554/live RTSP/1.0\r\nCSeq: 2\r\n\r\n")
        data2 = s2.recv(1024).decode("utf-8", errors="ignore")
        assert "RTSP/1.0 401 Unauthorized" in data2
        s2.close()
    finally:
        server.stop()

def test_fleet_manager_profiles_info():
    """Verify fleet manager successfully queries registered profile information."""
    profiles = get_available_profiles_info()
    assert len(profiles) >= 6
    ids = [p["id"] for p in profiles]
    assert "dlink_dcs932l" in ids
    assert "hikvision_ds2cd" in ids
    assert "dahua_ipc" in ids
    assert "open_access_cam" in ids
    assert "ip_webcam" in ids
    assert "hardened_cam" in ids

def test_fleet_manager_generate_compose(tmp_path):
    """Verify fleet manager can generate multi-container Docker Compose definitions."""
    from fleet_manager import generate_compose
    compose_path = str(tmp_path / "test_compose.yml")
    generate_compose(count=3, output_path=compose_path)
    assert os.path.exists(compose_path)
    with open(compose_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "mock-camera-01:" in content
    assert "mock-camera-02:" in content
    assert "mock-camera-03:" in content
    assert "vlan10_standard_iot:" in content
