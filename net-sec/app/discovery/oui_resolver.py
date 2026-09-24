"""
OUI (Organizationally Unique Identifier) MAC Address Resolver (net-sec)
Maps MAC prefixes to hardware manufacturers (IoT vendors, smartphone brands, etc.).
"""

OUI_DATABASE = {
    # IoT Vendors & Microcontrollers
    "18:FE:34": "Espressif Inc.",
    "24:0A:C4": "Espressif Inc.",
    "24:6F:28": "Espressif Inc.",
    "30:AE:A4": "Espressif Inc.",
    "40:22:D8": "Espressif Inc.",
    "5C:CF:7F": "Espressif Inc.",
    "60:01:94": "Espressif Inc.",
    "84:CC:A8": "Espressif Inc.",
    "A4:CF:12": "Espressif Inc.",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "28:CD:C1": "Raspberry Pi Trading",
    "70:B3:D5": "IEEE Registration Authority (IoT)",
    "00:1A:79": "Alcatel/Lucent IoT",
    "00:17:88": "Philips Lighting (Hue)",
    "EC:B5:FA": "Philips Lighting (Hue)",
    "00:0F:7D": "D-Link Corporation",
    "14:D6:4D": "D-Link Corporation",
    "28:10:7B": "D-Link Corporation",
    "C0:A0:BB": "D-Link Corporation",
    "00:18:FE": "Hewlett-Packard",
    "3C:33:00": "Hikvision Digital Technology",
    "44:19:B6": "Hikvision Digital Technology",
    "54:C4:15": "Hikvision Digital Technology",
    "C8:02:8F": "Hikvision Digital Technology",
    "38:AF:29": "Zhejiang Dahua Technology",
    "4C:11:BF": "Zhejiang Dahua Technology",
    "90:02:A9": "Zhejiang Dahua Technology",
    "E0:50:8B": "Zhejiang Dahua Technology",
    "50:C7:BF": "TP-Link Corporation",
    "60:A4:B7": "TP-Link Corporation",
    "70:4F:57": "TP-Link Corporation",
    "98:DA:C4": "TP-Link Corporation",
    "AC:84:C6": "TP-Link Corporation",
    "00:1D:CE": "Belkin International",
    "00:22:75": "Belkin International",
    "14:91:82": "Belkin International",
    "24:F5:A2": "Belkin International",
    "00:1A:2B": "Tuya Smart Inc.",
    "10:D0:7A": "Tuya Smart Inc.",
    "70:89:76": "Tuya Smart Inc.",
    "D8:BF:C0": "Tuya Smart Inc.",
    "00:04:20": "Slim Devices Inc.",
    "00:08:22": "InPro Comm (D-Link/Linksys)",
    "00:0E:8F": "Xiongmai Technologies (DVR/IPC)",
    "00:12:12": "Xiongmai Technologies",

    # Smartphone & Consumer Vendors
    "00:17:F2": "Apple, Inc.",
    "00:1E:C2": "Apple, Inc.",
    "00:23:12": "Apple, Inc.",
    "00:26:08": "Apple, Inc.",
    "04:0C:CE": "Apple, Inc.",
    "18:AF:61": "Apple, Inc.",
    "28:6A:B8": "Apple, Inc.",
    "34:15:9E": "Apple, Inc.",
    "78:7B:8A": "Apple, Inc.",
    "88:66:5A": "Apple, Inc.",
    "A4:C3:61": "Apple, Inc.",
    "BC:52:B7": "Apple, Inc.",
    "F4:37:B7": "Apple, Inc.",
    "00:07:AB": "Samsung Electronics",
    "00:12:47": "Samsung Electronics",
    "14:49:E0": "Samsung Electronics",
    "20:D5:BF": "Samsung Electronics",
    "2C:FD:A1": "Samsung Electronics",
    "34:23:87": "Samsung Electronics",
    "50:77:05": "Samsung Electronics",
    "64:16:66": "Samsung Electronics",
    "78:47:1D": "Samsung Electronics",
    "84:25:DB": "Samsung Electronics",
    "B4:07:C1": "Samsung Electronics",
    "34:CE:00": "Xiaomi Communications",
    "58:44:98": "Xiaomi Communications",
    "64:09:80": "Xiaomi Communications",
    "7C:49:EB": "Xiaomi Communications",
    "88:C3:97": "Xiaomi Communications",
    "A4:77:33": "Google, Inc.",
    "F4:F5:D8": "Google, Inc.",
    "3C:5A:37": "Google, Inc.",
    "F8:0F:F9": "Google, Inc.",
    "18:B4:30": "Nest Labs Inc.",
    "64:16:66": "Samsung Electronics",
    "50:E0:85": "Realtek Semiconductor",
    "C4:2C:7B": "Huawei Device Co., Ltd.",
    "2C:F0:5D": "Shenzhen Bilian Electronic",
    "90:09:DF": "Xiaomi Communications",
    "A8:A1:59": "Chongqing Fugui Electronics",
    "18:C0:4D": "Xiaomi Communications",
    "00:15:5D": "Microsoft Hyper-V Virtual NIC"
}

def resolve_mac_vendor(mac_address: str) -> str:
    """Normalize MAC address and lookup manufacturer name."""
    if not mac_address:
        return "Unknown"
    clean_mac = mac_address.replace("-", ":").upper().strip()
    parts = clean_mac.split(":")
    if len(parts) >= 3:
        prefix = ":".join(parts[:3])
        if prefix in OUI_DATABASE:
            return OUI_DATABASE[prefix]
    # Check if locally administered / randomized MAC (bit 1 of 1st byte is 1)
    try:
        first_byte = int(parts[0], 16)
        if (first_byte & 0x02) != 0:
            return "Randomized / Private MAC (Mobile Device)"
    except Exception:
        pass
    return "Unknown Vendor"
