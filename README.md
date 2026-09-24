# Insecure IoT Device Detection & Management Platform

**Course**: IT6027 - Cybersecurity Policy and Governance  
**Project Topic**: System for detecting insecure IoT devices within a network.

---

## 1. System Overview & Syllabus Mapping

This platform provides an end-to-end IoT environment and an independent security auditing system that strictly satisfies all course requirements:

| Requirement Category | Syllabus Item | Implementation Module | Technical Mechanism |
| :--- | :--- | :--- | :--- |
| **Mandatory** | IoT Device Fingerprinting | `net-sec/app/discovery/` & `scoping/classifier.py` | Service banner grabbing (HTTP/RTSP/Telnet/MQTT), mDNS Zeroconf listening, UPnP SSDP M-SEARCH XML parsing, OUI MAC vendor mapping. Classifies Cameras, Smart Plugs, Gateways, Sensors. |
| **Mandatory** | Firmware / CVE Matching | `net-sec/app/audit/cve_matcher.py` | Offline IoT CVE database (`cve_database.json`) correlating banners, vendors, and products to known CVEs with CVSS v3.1 scoring. |
| **Mandatory** | Default Password Auditing | `net-sec/app/audit/credential_checker.py` | Non-destructive authentication verifier testing against a predefined dictionary (`default_passwords.txt`) across HTTP Basic/Digest, Telnet, RTSP, and MQTT. |
| **Bonus** | VLAN-based Scoping | `net-sec/app/scoping/vlan_scoper.py` | Maps subnets to VLANs (Hotspot WLAN, Standard IoT VLAN 10, Quarantine VLAN 99). Evaluates zero-trust isolation policies for insecure devices. |
| **Bonus** | Real-Time Alerts | `net-sec/app/scanner_engine.py` | Generates real-time alerts on Critical/High CVEs and default password detections. |
| **Bonus** | Device-Type Dashboard | `net-sec/app/web/` | Interactive, responsive web dashboard (Tailwind CSS, dark mode, KPI cards, device inspector, governance report generator). |

---

## 2. Repository Layout

```
iot-system/
├── _antigravity/                          # Requirements and draft specs
├── net-infrastructure/                    # Physical edge network setup
│   ├── setup_hotspot.ps1                  # PowerShell helper for Windows Mobile Hotspot
│   ├── hotspot_guide.md                   # Setup guide for Wi-Fi AP & smartphones
│   └── network_diagnostics.py             # Interface & ARP discovery diagnostic tool
├── net-core/                              # Core IoT services
│   ├── mosquitto/                         # Mosquitto MQTT broker configuration & runner
│   │   ├── mosquitto.conf
│   │   └── run_mosquitto.ps1
│   └── iot_gateway.py                     # Central HTTP/MQTT telemetry registry & hub
├── mock-object/                           # Scaling templates & blueprints for Docker
│   ├── README.md                          # Blueprint guide for scaling
│   ├── docker-compose.template.yml        # Multi-VLAN Compose template
│   └── templates/                         # Emulation templates (Camera, SmartPlug, DVR)
├── net-sec/                               # Independent security auditor & dashboard
│   ├── requirements.txt
│   ├── run_scanner.py                     # Unified CLI & Web dashboard launcher
│   ├── app/
│   │   ├── scanner_engine.py              # Central orchestrator
│   │   ├── discovery/                     # mDNS, UPnP, Port Scanner, Banner Grabber, OUI
│   │   ├── audit/                         # CVE Matcher, Default Password Checker, Wordlist
│   │   ├── scoping/                       # Device Classifier, VLAN Scoper & Quarantine
│   │   └── web/                           # FastAPI server & responsive Web Dashboard
│   └── tests/                             # Unit & integration test suite (17 tests)
└── README.md
```

---

## 3. Quick Start Guide

### Step 1: Establish Physical Edge IoT Network (`net-infrastructure`)
1. Enable Windows Mobile Hotspot (SSID: `IoT-Edge-Network`, Subnet: `192.168.137.0/24`):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\net-infrastructure\setup_hotspot.ps1 -Action Status
   ```
2. Connect your smartphone to the hotspot.
3. On Smartphone 1: Launch **IP Webcam** (default streaming on port `8080`).
4. On Smartphone 2: Connect an MQTT client app to `192.168.137.1:1883` or send sensor telemetry.
5. Verify connected nodes via diagnostics:
   ```powershell
   python .\net-infrastructure\network_diagnostics.py
   ```

### Step 2: Start IoT Core Services (`net-core`)
Start the IoT Gateway and Telemetry Registry:
```powershell
python .\net-core\iot_gateway.py
```
*(Optional: Run Mosquitto MQTT broker via `powershell .\net-core\mosquitto\run_mosquitto.ps1 -Action start`)*

### Step 3: Launch Security Auditor & Dashboard (`net-sec`)
Start the interactive Web Dashboard:
```powershell
python .\net-sec\run_scanner.py --web --port 8000
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser:
- Click **"Start Network Audit"** to discover devices across the edge subnet (`192.168.137.0/24`).
- Review device fingerprints (Camera, Smart Plug, Gateway, Sensor).
- Check matched CVEs and default password alert violations.
- View VLAN scoping recommendations (quarantining insecure devices to VLAN 99).
- Click **"Governance Report"** to export an academic-grade markdown/printable audit summary.

Alternatively, perform a CLI-only scan:
```powershell
python .\net-sec\run_scanner.py --scan --target 192.168.137.0/24
```

---

## 4. Running Automated Tests

Run the full pytest suite (17 tests covering classification, CVE matching, credential auditing, and VLAN scoping):
```powershell
python -m pytest "net-sec\tests" -v
```

---

## 5. Scaling with Mock Objects (`mock-object`)

When you wish to scale beyond physical smartphones to 10+ devices across simulated VLANs:
```powershell
# See instructions in mock-object/README.md
docker compose -f .\mock-object\docker-compose.template.yml up -d
```
All mock containers receive static IPs on `172.28.10.0/24`, allowing `net-sec` to audit them as independent physical-like endpoints without port conflicts.
