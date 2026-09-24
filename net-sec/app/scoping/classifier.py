"""
Device Type Classifier (net-sec)
Categorizes devices into functional IoT classes (Cameras, Smart Plugs, Gateways, Sensors, Smartphones)
based on banners, mDNS announcements, UPnP device types, and open ports.
"""

from typing import Dict, Any, List

def classify_device(device: Dict[str, Any]) -> str:
    """
    Determine the high-level device category.
    Returns: 'IP Camera', 'Smart Plug', 'IoT Gateway / Router',
             'IoT Sensor Node', 'Smartphone / Mobile Device', or 'Generic IoT Device'
    """
    ports: List[int] = device.get("open_ports", [])
    banners: Dict[str, Any] = device.get("banners", {})
    upnp_meta: Dict[str, str] = device.get("upnp_meta", {})
    mdns_services: List[str] = [s.get("type", "") for s in device.get("mdns_services", [])]
    vendor: str = str(device.get("vendor", "")).lower()
    model: str = str(device.get("model", "")).lower()
    
    # Check all banner text
    banner_text = ""
    for k, v in banners.items():
        if isinstance(v, dict):
            banner_text += " " + " ".join([str(val) for val in v.values()])
        elif isinstance(v, str):
            banner_text += " " + v
    banner_text = banner_text.lower()
    upnp_text = " ".join([str(v) for v in upnp_meta.values()]).lower()
    all_text = f"{banner_text} {upnp_text} {vendor} {model}"

    # 1. IP Camera classification
    if 554 in ports:
        return "IP Camera"
    if any(cam in all_text for cam in ["camera", "ipcam", "ip webcam", "webcam", "video server", "dcs-", "hikvision", "dahua", "surveillance"]):
        return "IP Camera"
    if any(s in mdns_services for s in ["_camera._tcp.local.", "_axis-video._tcp.local.", "_rtsp._tcp.local."]):
        return "IP Camera"
    if "digitalsecuritycamera" in upnp_text:
        return "IP Camera"

    # 2. Smart Plug classification
    if any(plug in all_text for plug in ["smart plug", "smart switch", "wemo", "hs100", "hs110", "kasa", "sonoff", "shelly"]):
        return "Smart Plug"
    if "_smartplug._tcp.local." in mdns_services or 9999 in ports:
        return "Smart Plug"
    if "controllee" in upnp_text or "smartplug" in upnp_text:
        return "Smart Plug"

    # 3. IoT Gateway / Router classification
    if 23 in ports or "busybox" in all_text or "internetgatewaydevice" in upnp_text:
        return "IoT Gateway / Router"
    if any(r in all_text for r in ["router", "gateway", "access point", "modem", "dvr"]):
        return "IoT Gateway / Router"

    # 4. IoT Sensor / Actuator Node
    if 1883 in ports or "mqtt" in all_text or "_mqtt._tcp.local." in mdns_services:
        return "IoT Sensor Node"

    # 5. Smartphone / Mobile Device
    if any(s in mdns_services for s in ["_apple-mobdev2._tcp.local.", "_googlecast._tcp.local.", "_android-remote._tcp.local."]):
        return "Smartphone / Mobile Device"
    if any(phone_vendor in vendor for phone_vendor in ["apple", "samsung", "xiaomi", "huawei", "google"]):
        return "Smartphone / Mobile Device"
    if "mobile device" in vendor or "randomized / private mac" in vendor:
        return "Smartphone / Mobile Device"
    if any(brand in all_text for brand in ["xiaomi", "redmi", "iphone", "ipad", "android", "pixel", "galaxy", "oppo", "vivo", "oneplus"]):
        return "Smartphone / Mobile Device"

    # Fallback
    return "Generic IoT Device"
