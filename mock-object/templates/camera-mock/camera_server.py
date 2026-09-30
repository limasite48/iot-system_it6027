#!/usr/bin/env python3
"""
Simulated Legacy IP Camera (mock-object template)
Emulates a D-Link DCS-932L IP Camera.
Powered by the modular Camera Emulation Engine.
"""

import os
import sys
from http.server import HTTPServer

# Add engine directory to sys.path
ENGINE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "engine"))
if ENGINE_DIR not in sys.path:
    sys.path.insert(0, ENGINE_DIR)

from camera_server import (
    load_profile,
    generate_upnp_xml,
    DynamicCameraHTTPHandler,
    DynamicCameraRTSPServer,
    DynamicSSDPResponder,
    DynamicMDNSAdvertiser,
    CameraServer,
    DEFAULT_PROFILE
)

# Backward-compatible CameraHTTPHandler for test_integration.py
class CameraHTTPHandler(DynamicCameraHTTPHandler):
    server_profile = load_profile("dlink_dcs932l")

def run_ssdp_responder(http_port=8080):
    responder = DynamicSSDPResponder(http_port, load_profile("dlink_dcs932l"))
    responder.start()
    return responder

def run_rtsp_server(port=554):
    server = DynamicCameraRTSPServer(port, load_profile("dlink_dcs932l"))
    server.start()
    return server

def run_mdns_advertiser(http_port=8080):
    advertiser = DynamicMDNSAdvertiser(http_port, load_profile("dlink_dcs932l"))
    advertiser.start()
    return advertiser

if __name__ == "__main__":
    profile_name = os.environ.get("CAMERA_PROFILE", "dlink_dcs932l")
    http_port = int(os.environ.get("HTTP_PORT", "8080"))
    rtsp_port = int(os.environ.get("RTSP_PORT", "554"))
    bind_ip = os.environ.get("BIND_IP", "0.0.0.0")

    server = CameraServer(profile_name_or_dict=profile_name, http_port=http_port, rtsp_port=rtsp_port, ip=bind_ip)
    server.start(blocking=True)
