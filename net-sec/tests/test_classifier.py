import pytest
from app.scoping.classifier import classify_device

def test_classify_camera_by_rtsp_port():
    device = {
        "open_ports": [554, 80],
        "banners": {},
        "upnp_meta": {},
        "mdns_services": []
    }
    assert classify_device(device) == "IP Camera"

def test_classify_camera_by_banner():
    device = {
        "open_ports": [8080],
        "banners": {
            "http_8080": {"title": "IP Webcam Live Stream", "server": "IP Webcam Server"}
        },
        "upnp_meta": {},
        "mdns_services": []
    }
    assert classify_device(device) == "IP Camera"

def test_classify_smartplug_by_upnp():
    device = {
        "open_ports": [80],
        "banners": {},
        "upnp_meta": {
            "device_type": "urn:Belkin:device:controllee:1",
            "model_name": "WeMo Switch"
        },
        "mdns_services": []
    }
    assert classify_device(device) == "Smart Plug"

def test_classify_gateway_by_telnet():
    device = {
        "open_ports": [23, 80],
        "banners": {
            "telnet_23": "BusyBox v1.1.2 Built-in shell (ash)"
        },
        "upnp_meta": {},
        "mdns_services": []
    }
    assert classify_device(device) == "IoT Gateway / Router"

def test_classify_sensor_by_mqtt():
    device = {
        "open_ports": [1883],
        "banners": {},
        "upnp_meta": {},
        "mdns_services": []
    }
    assert classify_device(device) == "IoT Sensor Node"

def test_classify_smartphone():
    device = {
        "open_ports": [],
        "banners": {},
        "upnp_meta": {},
        "mdns_services": [{"type": "_apple-mobdev2._tcp.local."}],
        "vendor": "Apple, Inc."
    }
    assert classify_device(device) == "Smartphone / Mobile Device"
