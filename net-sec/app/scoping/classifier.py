"""
Device Type Classifier (net-sec)
Categorizes devices into functional IoT classes (Cameras, Smart Plugs, Gateways, Sensors, Smartphones)
based on banners, mDNS announcements, UPnP device types, and open ports.
"""

from typing import Dict, Any, List

def classify_device(device: Dict[str, Any]) -> str:
    """
    Determine the high-level device category.
    Returns: 'IP Camera', 'Smart TV / Media Player', 'Smart Air Conditioner / HVAC',
             'Smart Fan / Air Purifier', 'Smart Thermostat', 'Smart Plug',
             'IoT Gateway / Router', 'IoT Sensor Node', 'Smartphone / Mobile Device',
             or 'Generic IoT Device'
    """
    explicit_category = device.get("device_category")
    if explicit_category:
        return explicit_category

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
    all_text = f" {banner_text} {upnp_text} {vendor} {model} "

    # 1. IP Camera classification
    if 554 in ports:
        return "IP Camera"
    if any(cam in all_text for cam in ["camera", "ipcam", "ip webcam", "webcam", "video server", "dcs-", "hikvision", "dahua", "surveillance"]):
        return "IP Camera"
    if any(s in mdns_services for s in ["_camera._tcp.local.", "_axis-video._tcp.local.", "_rtsp._tcp.local."]):
        return "IP Camera"
    if "digitalsecuritycamera" in upnp_text:
        return "IP Camera"

    # 2. Smart TV / Media Player classification
    if any(p in ports for p in [3000, 3001, 8001, 8002]) and any(tv in all_text for tv in ["tv", "tizen", "webos", "samsung", "lg", "sony", "bravia", "media"]):
        return "Smart TV / Media Player"
    if any(tv in all_text for tv in ["smart tv", "smart-tv", "smarttv", "tizen", "webos", "bravia", "appletv", "chromecast", "roku", "firetv", "television", "oled55", "un55ru"]):
        return "Smart TV / Media Player"
    if "mediarenderer" in upnp_text or any(s in mdns_services for s in ["_googlecast._tcp.local.", "_airplay._tcp.local.", "_raop._tcp.local.", "_webos-second-screen._tcp.local."]):
        return "Smart TV / Media Player"

    # 3. Smart Air Conditioner / HVAC classification
    if any(ac in all_text for ac in ["air conditioner", "aircon", "hvac", "daikin", "airbase", "brp069", "gree", "midea", "inverter ac", "climate control"]):
        return "Smart Air Conditioner / HVAC"
    if "hvac" in upnp_text or any(s in mdns_services for s in ["_daikin._tcp.local.", "_hvac._tcp.local."]):
        return "Smart Air Conditioner / HVAC"

    # 4. Smart Thermostat classification
    if any(tstat in all_text for tstat in ["thermostat", "tstat", "radio thermostat", "radiothermostat", "ecobee", "nest", "honeywell", "ct50", "ct80", "ct30"]):
        return "Smart Thermostat"
    if "thermostat" in upnp_text or "_thermostat._tcp.local." in mdns_services:
        return "Smart Thermostat"

    # 5. Smart Fan / Air Purifier classification
    if any(fan in all_text for fan in ["smart fan", "air purifier", "dyson", "pure cool", "mi smart standing fan", "standing fan", "desk fan", "fan / purifier"]):
        return "Smart Fan / Air Purifier"
    if "airpurifier" in upnp_text or any(s in mdns_services for s in ["_fan._tcp.local.", "_airpurifier._tcp.local."]):
        return "Smart Fan / Air Purifier"

    # 6. Smart Plug classification
    if any(plug in all_text for plug in ["smart plug", "smart switch", "wemo", "hs100", "hs110", "kasa", "sonoff", "shelly"]):
        return "Smart Plug"
    if "_smartplug._tcp.local." in mdns_services or 9999 in ports:
        return "Smart Plug"
    if "controllee" in upnp_text or "smartplug" in upnp_text:
        return "Smart Plug"

    # 7. IoT Gateway / Router classification
    if 23 in ports or "busybox" in all_text or "internetgatewaydevice" in upnp_text:
        return "IoT Gateway / Router"
    if any(r in all_text for r in ["router", "gateway", "access point", "modem", "dvr"]):
        return "IoT Gateway / Router"

    # 8. IoT Sensor / Actuator Node
    if 1883 in ports or "mqtt" in all_text or "_mqtt._tcp.local." in mdns_services:
        return "IoT Sensor Node"

    # 9. Smartphone / Mobile Device (Evaluated after specific smart appliances)
    if any(s in mdns_services for s in ["_apple-mobdev2._tcp.local.", "_android-remote._tcp.local."]):
        return "Smartphone / Mobile Device"
    if any(phone_vendor in vendor for phone_vendor in ["apple", "samsung", "xiaomi", "huawei", "google"]):
        return "Smartphone / Mobile Device"
    if "mobile device" in vendor or "randomized / private mac" in vendor:
        return "Smartphone / Mobile Device"
    if any(brand in all_text for brand in ["xiaomi", "redmi", "iphone", "ipad", "android", "pixel", "galaxy", "oppo", "vivo", "oneplus"]):
        return "Smartphone / Mobile Device"

    # Fallback
    return "Generic IoT Device"
