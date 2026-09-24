# Physical IoT Network Setup Guide (`net-infrastructure`)

This guide explains how to establish the physical edge IoT network using your Windows laptop as the Wi-Fi Access Point / Router and your smartphones as authentic IoT edge devices.

---

## 1. Enable Windows Mobile Hotspot

### Method A: Via Windows Settings (Recommended)
1. Open Windows Settings (`Win + I`) -> **Network & Internet** -> **Mobile hotspot**.
   *(Or press `Win + R`, type `ms-settings:network-mobilehotspot`, and hit Enter).*
2. Configure your Network properties:
   - **Network name (SSID)**: e.g. `IoT-Edge-Network`
   - **Network band**: 2.4 GHz or Any (2.4 GHz ensures compatibility with older devices/apps)
   - **Network password**: Set a Wi-Fi password (e.g., `IoTSecurity2026!`)
3. Toggle Mobile Hotspot to **ON**.
4. By default, Windows assigns the laptop's virtual Wi-Fi adapter IP `192.168.137.1` and runs an internal DHCP server leasing addresses in `192.168.137.2` – `192.168.137.254`.

### Method B: Via PowerShell Helper
From the repository root:
```powershell
powershell -ExecutionPolicy Bypass -File .\net-infrastructure\setup_hotspot.ps1 -Action Status
```
To enable programmatically:
```powershell
powershell -ExecutionPolicy Bypass -File .\net-infrastructure\setup_hotspot.ps1 -Action Enable
```

---

## 2. Connect and Configure Smartphones as IoT Devices

Connect your smartphones to the Wi-Fi SSID configured above (`IoT-Edge-Network`).

### Device 1: Physical IP Camera (Smartphone 1)
1. Install an IP camera streaming app from Google Play Store / App Store:
   - **Android Recommendation**: **IP Webcam** by Pavel Khlebovich (Free on Play Store) or **DroidCam**.
   - **iOS Recommendation**: **RTSP Camera** or **Live-Reporter**.
2. Open **IP Webcam**:
   - Scroll to **Video preferences** -> Set resolution (e.g., 640x480 for fast performance).
   - Under **Connection settings**:
     - Optional test: Enable "Local broadcasting" / Basic HTTP login. You can set `admin/admin` or leave it open to simulate an insecure default camera.
   - Scroll to the bottom and tap **"Start server"**.
3. Note the displayed URL (e.g., `http://192.168.137.x:8080` and `rtsp://192.168.137.x:8080/h264_pcm.sdp`).
4. Test from your laptop browser: open `http://192.168.137.x:8080`. You should see the IP Webcam web interface and live video feed.

### Device 2: Physical IoT Sensor / Telemetry Client (Smartphone 2)
1. Install an MQTT client app:
   - **Android / iOS**: **MQTT Dash**, **IoT MQTT Panel**, or **MQTT Analyzer**.
2. Configure broker connection:
   - **Broker IP**: `192.168.137.1` (the laptop's IP on the hotspot network)
   - **Port**: `1883`
   - **Client ID**: e.g. `smart-sensor-01`
3. Publish periodic sensor telemetry or button presses to topic:
   - Topic: `iot/sensors/livingroom/temperature`
   - Payload: `{"temp": 26.5, "humidity": 60, "battery": 92}`

---

## 3. Verify Edge Subnet with Network Diagnostics

Run the diagnostics script on your laptop:
```powershell
python .\net-infrastructure\network_diagnostics.py
```
This utility:
- Automatically detects the Hotspot adapter and local IP.
- Reads the ARP cache to identify connected smartphones and their MAC addresses.
- Displays round-trip ping latency.
