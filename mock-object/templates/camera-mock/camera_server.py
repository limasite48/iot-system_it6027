#!/usr/bin/env python3
"""
Simulated Legacy IP Camera (mock-object template)
Emulates a D-Link DCS-932L IP Camera.
Powered by the modular Camera Emulation Engine.
"""

import os
import sys
import importlib.util
from http.server import HTTPServer

# Locate engine directory (supports both repo structure and Docker /app structure)
_base_dir = os.path.dirname(os.path.abspath(__file__))
_repo_engine = os.path.abspath(os.path.join(_base_dir, "..", "..", "engine"))
_docker_engine = os.path.abspath(os.path.join(_base_dir, "engine"))

if os.path.isdir(_repo_engine):
    ENGINE_DIR = _repo_engine
elif os.path.isdir(_docker_engine):
    ENGINE_DIR = _docker_engine
else:
    ENGINE_DIR = _repo_engine

_engine_file = os.path.join(ENGINE_DIR, "camera_server.py")
if not os.path.isfile(_engine_file):
    raise FileNotFoundError(f"Cannot find camera emulation engine at {_engine_file}")

_spec = importlib.util.spec_from_file_location("camera_engine_core", _engine_file)
_engine_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_engine_mod)

load_profile = _engine_mod.load_profile
generate_upnp_xml = _engine_mod.generate_upnp_xml
DynamicCameraHTTPHandler = _engine_mod.DynamicCameraHTTPHandler
DynamicCameraRTSPServer = _engine_mod.DynamicCameraRTSPServer
DynamicSSDPResponder = _engine_mod.DynamicSSDPResponder
DynamicMDNSAdvertiser = _engine_mod.DynamicMDNSAdvertiser
CameraServer = _engine_mod.CameraServer
DEFAULT_PROFILE = _engine_mod.DEFAULT_PROFILE

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
    http_env = os.environ.get("HTTP_PORT", "")
    http_port = int(http_env) if http_env and http_env.isdigit() else None
    rtsp_env = os.environ.get("RTSP_PORT", "")
    rtsp_disabled = rtsp_env.lower() in ("disabled", "none", "false", "0", "off")
    rtsp_port = int(rtsp_env) if rtsp_env and rtsp_env.isdigit() else None
    bind_ip = os.environ.get("BIND_IP", "0.0.0.0")

    prof = load_profile(profile_name)
    if rtsp_disabled:
        prof["rtsp_enabled"] = False

    server = CameraServer(profile_name_or_dict=prof, http_port=http_port, rtsp_port=rtsp_port, ip=bind_ip)
    server.start(blocking=True)
