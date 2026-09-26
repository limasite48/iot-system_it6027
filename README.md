# Insecure IoT Device Detection & Management Platform

**Course**: IT6027 - Cybersecurity Policy and Governance  
**Project Topic**: System for detecting insecure IoT devices within a network.  
**Test Suite**: 67 Passing Automated Tests (`pytest net-sec/tests -v`)

---

## 1. System Overview & Syllabus Mapping

This platform provides an end-to-end IoT environment and an independent security auditing system strictly designed for **IoT edge networks** (IP cameras, smart plugs, DVRs, environmental sensors, and IoT gateways). It strictly adheres to all course requirements, combining active protocol discovery with non-destructive vulnerability auditing, declarative security policies, auditor triage workflows, and zero-trust micro-segmentation.

| Requirement Category | Syllabus Item | Implementation Module | Technical Mechanism |
| :--- | :--- | :--- | :--- |
| **Mandatory** | IoT Device Fingerprinting | `net-sec/app/discovery/` & `scoping/classifier.py` | Multi-vector fingerprinting: Service banner grabbing (HTTP/RTSP/Telnet/MQTT), mDNS Zeroconf listening, UPnP SSDP M-SEARCH XML parsing, OUI MAC vendor mapping. Classifies Cameras, Smart Plugs, Gateways, Sensors, Smartphones. |
| **Mandatory** | Firmware / CVE Matching | `net-sec/app/audit/cpe_normalizer.py` & `cve_matcher.py` | Official NIST CPE 2.3 URI/formatted string builder (`cpe:2.3:h:vendor:product:version:...`) paired with SemVer comparative analysis against offline database (`cve_database.json`) with CVSS v3.1 scoring. |
| **Mandatory** | Default Password Auditing | `net-sec/app/audit/credential_checker.py` | Non-destructive authentication verifier testing against predefined credential dictionaries (`default_passwords.txt`) across HTTP Basic/Digest, Telnet, RTSP, and MQTT protocols. |
| **Bonus** | Declarative Policy Engine | `net-sec/app/audit/policy_engine.py` & `policies/` | Human-readable YAML governance policies (`iot_hardening_rules.yaml`) validated by JSON Schema (`policy_schema.json`), checking password exposure, cleartext Telnet, open video feeds, and anonymous MQTT. |
| **Bonus** | Auditor Triage Workflow | `net-sec/app/audit/triage.py` | Governance audit workflow enabling security analysts to review findings, approve violations, mark false positives, or suppress alerts with mandatory auditor notes. |
| **Bonus** | VLAN Micro-Segmentation | `net-sec/app/scoping/vlan_scoper.py` | Zero-Trust dynamic policy enforcement table mapping subnets to VLANs (Hotspot WLAN, Standard IoT VLAN 10, Quarantine VLAN 99). Evaluates isolation policies for insecure endpoints. |
| **Bonus** | Real-Time Alerts & Webhooks | `net-sec/app/monitoring/alert_dispatcher.py` | Immediate alert streaming and outbound JSON webhook notifications (Slack, Discord, SIEM/Syslog) triggered on Critical/High risks and default password detections. |
| **Bonus** | Responsive Web Dashboard | `net-sec/app/web/` | Modern Tailwind CSS dashboard with vertical sidebar navigation, real-time device cards, interactive SVG network topology map, live RTSP video preview, scan pipeline stage tracking, and academic report generator. |

---

## 2. Repository Layout

```
iot-system/
├── _antigravity/                          # Requirements and draft specifications
│   ├── project_draft.md                   # Complete architectural & technical specification
│   ├── project_requirements.md            # Course requirements & grading rubrics
│   └── ref_1.md                           # Reference project analysis
├── docker-compose.yml                     # Multi-container root orchestrator (Auditor + IoT Gateway)
├── net-infrastructure/                    # Physical edge network setup
│   ├── setup_hotspot.ps1                  # PowerShell helper for Windows Mobile Hotspot
│   ├── hotspot_guide.md                   # Setup guide for Wi-Fi AP & smartphones
│   └── network_diagnostics.py             # Interface & ARP discovery diagnostic tool
├── net-core/                              # Core IoT services
│   ├── mosquitto/                         # Mosquitto MQTT broker configuration & runner
│   │   ├── mosquitto.conf
│   │   └── run_mosquitto.ps1
│   ├── iot_gateway.py                     # Central HTTP/MQTT telemetry registry & hub
│   └── Dockerfile                         # Lightweight container for IoT Gateway
├── mock-object/                           # Scaling templates & blueprints for Docker
│   ├── README.md                          # Blueprint guide for scaling
│   ├── docker-compose.template.yml        # Multi-VLAN Compose template
│   └── templates/                         # Emulation templates (Camera, SmartPlug, DVR)
├── net-sec/                               # Independent security auditor & dashboard
│   ├── Dockerfile                         # Production container for Security Auditor
│   ├── requirements.txt
│   ├── run_scanner.py                     # Unified CLI & Web dashboard launcher
│   ├── policies/                          # Declarative governance policies
│   │   ├── iot_hardening_rules.yaml       # Course compliance rules (default credentials, telnet, rtsp)
│   │   └── policy_schema.json             # JSON Schema validator for policies
│   ├── app/
│   │   ├── scanner_engine.py              # Central orchestrator with 7-stage pipeline tracking
│   │   ├── discovery/                     # mDNS, UPnP, Port Scanner, Banner Grabber, OUI
│   │   ├── audit/                         # CPE Normalizer, CVE Matcher, Credential Checker, Policy Engine, Triage
│   │   ├── scoping/                       # Device Classifier, VLAN Scoper, CIDR Scope Service
│   │   ├── monitoring/                    # Real-time Alert & Webhook Dispatcher
│   │   └── web/                           # FastAPI server & responsive Web Dashboard
│   │       ├── api.py                     # RESTful API endpoints (/api/scan, /api/triage, /api/report, etc.)
│   │       └── static/
│   │           └── index.html             # Vertical sidebar UI with SVG topology & triage tables
│   └── tests/                             # Full automated test suite (67 tests)
└── README.md
```

---

## 3. Quick Start & Execution Instructions

You can run the platform locally on Windows (recommended for direct access to physical Mobile Hotspot / Wi-Fi adapters) or inside isolated Docker containers.

### Method A: Local Native Execution (Recommended)

1. **Install Prerequisites**:
   - Python 3.10+ (tested on Python 3.14 on Windows 11).
   - Install auditor dependencies:
     ```powershell
     cd net-sec
     pip install -r requirements.txt
     cd ..
     ```

2. **Launch Interactive Web Dashboard**:
   ```powershell
   python net-sec\run_scanner.py --web --port 8000
   ```
   Open **[http://localhost:8000](http://localhost:8000)** in your web browser.

3. **(Optional) Run IoT Edge Gateway in a separate terminal**:
   ```powershell
   python net-core\iot_gateway.py
   ```
   Gateway listens on port `5000` (telemetry registry and device status hub).

---

### Method B: Docker Compose Multi-Container Run

To spin up both the Security Auditor dashboard and the IoT Core Gateway simultaneously in isolated Docker networks:

```powershell
# Build and run auditor and core gateway
docker compose up --build -d
```

- **Auditor Web Dashboard**: `http://localhost:8000`
- **IoT Core Gateway**: `http://localhost:5000`
- **View Container Logs**: `docker compose logs -f`
- **Stop Containers**: `docker compose down`

---

### Method C: Command-Line (CLI) Audit Mode

Perform a non-interactive, headless network audit scan directly from PowerShell or Bash:

```powershell
python net-sec\run_scanner.py --scan --target 192.168.137.0/24
```

The CLI prints structured tables detailing:
- Discovered devices and classified hardware categories.
- Fingerprints (MAC, OUI Vendor, banners, open ports).
- Matched CVEs and CVSS v3.1 severity scores.
- Default password audit outcomes.
- Recommended VLAN isolation (Quarantine VLAN 99).

---

### Physical Edge Setup (Smartphones & Hotspot)

To audit actual physical devices (e.g. Android/iPhone running IP Webcam or smart appliances):

1. **Enable Windows Mobile Hotspot** (`192.168.137.0/24`):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\net-infrastructure\setup_hotspot.ps1 -Action Status
   ```
2. **Connect Smartphone to Hotspot**:
   - On Smartphone 1: Start **IP Webcam** (streams on port `8080`).
   - On Smartphone 2: Connect an MQTT client app publishing to `192.168.137.1:1883`.
3. **Verify Network Connectivity**:
   ```powershell
   python .\net-infrastructure\network_diagnostics.py
   ```

---

## 4. Web Dashboard Function Guide

The web dashboard at `http://localhost:8000` has been engineered with a clean **vertical sidebar layout** to streamline multi-tab navigation without horizontal overflow.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  IoT Security Audit Hub   [Target: 192.168.137.0/24]  [Start Network Audit]  [Report]  │
├──────────────┬─────────────────────────────────────────────────────────────────────────┤
│ [=] Overview │                                                                         │
│              │  KPI Summary Cards: Discovered Devices | Critical Risks | Quarantine    │
│ [1] Devices  │                                                                         │
│ [2] Topology │  ACTIVE VIEW AREA:                                                      │
│ [3] Triage   │  - Device Cards with live streaming previews                            │
│ [4] VLANs    │  - Interactive SVG Node-Link Topology Graph                             │
│ [5] Scans    │  - Auditor Governance & Triage Action Table                             │
│ [6] Alerts   │  - Zero-Trust VLAN Micro-Segmentation Quarantine Matrix                 │
│              │  - 7-Stage Scan Pipeline & Execution History                            │
│ [*] Webhooks │  - Real-Time Critical Alert Stream & Outbound Webhook Integrations      │
└──────────────┴─────────────────────────────────────────────────────────────────────────┘
```

### 1. Global Header & Control Bar
- **Target Subnet Input**: Allows the user to specify CIDR targets (default: `192.168.137.0/24`). Verified against pre-scan scope rules to prevent unauthorized scanning of public WAN or upstream corporate networks.
- **Start Network Audit Button**: Initiates an audit with instant 0ms UI reactivity. The scan engine executes mDNS, UPnP SSDP, and port sweeps concurrently in non-blocking background threads.
- **Scan Pipeline Stage Tracker**: Visual progress pill indicating active execution stages (`STAGE_1_SCOPE_VERIFICATION` through `STAGE_7_COMPLETED`).
- **Governance Report Button**: Downloads and displays an academic-grade markdown audit report detailing findings, risk posture, and ISO/IEC 27402 remediation recommendations.
- **Theme Toggle**: Switch between dark mode and high-contrast light mode.

### 2. Tab 1: Device Inventory & Fingerprints
- **Device KPI Cards**: Displays total discovered endpoints, categorized by device type (IP Camera, Smart Plug, IoT Gateway, Environmental Sensor, Smartphone).
- **Hardware & Protocol Metadata**: Shows IP address, MAC address, IEEE OUI manufacturer name, and open IoT ports.
- **Live Stream Preview**: Directly connects to detected HTTP/RTSP video streaming endpoints (e.g. IP Webcam port `8080`) providing live visual feeds inside the audit card.
- **CVE Matches**: Displays correlated CVE identifiers, CVSS v3.1 severity scores (Critical, High, Medium, Low), and vulnerability descriptions based on CPE 2.3 matching.
- **Default Credential Flags**: Highlights red alert tags when devices permit access via default credentials (`admin:admin`, `admin:123456`, `root:root`) or unauthenticated open streaming.

### 3. Tab 2: Visual Network Topology Map
- **Interactive SVG Node Graph**: Visualizes the edge topology:
  - **Gateway Node**: Center router / auditor hub (`192.168.137.1`).
  - **Network Segments**: Hotspot WLAN (`192.168.137.0/24`) and Standard IoT Subnet (`172.28.10.0/24`).
  - **Device Nodes**: Dynamically positioned and color-coded (Green for compliant, Amber for low/medium risk, Red for critical CVEs or default passwords).
  - **Quarantine Zone**: Dedicated visual boundary representing **VLAN 99** for isolated rogue devices.

### 4. Tab 3: Auditor Governance & Triage
- **Finding Review**: Displays an audit table of all detected vulnerabilities and policy violations.
- **Triage Actions**: Auditors can take governance actions:
  - **Approve Violation**: Validates that the risk is authentic and flags it for mandatory remediation or isolation.
  - **False Positive**: Marks a finding as non-applicable with auditor rationale.
  - **Suppress Alert**: Temporarily silences an alert during ongoing maintenance.
- **Auditor Notes**: Analysts can attach mandatory governance notes before committing status changes to the persistent audit ledger (`triage_state.json`).

### 5. Tab 4: VLAN Micro-Segmentation
- **Zero-Trust Containment Matrix**: Evaluates dynamic isolation policies based on device risk posture.
- **Isolation Rules**: Any device triggering a Critical CVE (CVSS $\ge$ 9.0), cleartext default password exposure, or open RTSP stream is automatically flagged for quarantine.
- **Recommended Actions**:
  - Assign to **VLAN 99 (Quarantine)** via 802.1Q tag.
  - Apply firewall rules blocking east-west traffic to other IoT nodes while restricting outbound WAN access.

### 6. Tab 5: Scan Pipeline & History
- **Persistent Scan Ledger**: Maintains a timestamped history of previous network audits.
- **Audit Metrics**: Displays `scan_id`, target subnet CIDR, elapsed scan time (seconds), total discovered devices, detected vulnerabilities, and final scan status.

### 7. Tab 6: Real-time Alerts & Webhooks
- **Urgent Notification Stream**: High-priority alert banner listing critical security events discovered during the latest scan.
- **Webhook Dispatcher**: Integrates with external security monitoring tools:
  - Supports Slack, Discord, and Syslog webhook endpoints.
  - Can be tested directly from the dashboard via the **Test Webhook** button.

---

## 5. Automated Test Suite

The project includes an automated test suite with **67 comprehensive tests** covering all modules:

```powershell
# Run the complete test suite from repository root:
python -m pytest "net-sec\tests" -v
```

### Test Coverage Breakdown:
- **`test_cpe_normalizer.py` (7 tests)**: Validates NIST CPE 2.3 string formatting, SemVer version extraction, and real-world CVE matching for D-Link, Xiongmai DVR, TP-Link, Hikvision, and Realtek mini_upnpd.
- **`test_policy_engine.py` (7 tests)**: Validates declarative YAML policy loading, JSON schema validation, and enforcement of default credential, open RTSP stream, and cleartext Telnet rules.
- **`test_scope_service.py` (7 tests)**: Ensures pre-scan target verification permits authorized subnets while strictly rejecting loopback (`127.0.0.1`), upstream home LANs, and public WAN addresses.
- **`test_triage.py` (4 tests)**: Tests auditor triage lifecycle (Pending $\rightarrow$ Approved / Rejected / Suppressed) and state persistence.
- **`test_classifier.py` (6 tests)**: Validates multi-vector classification (Camera by RTSP/banner, Smart Plug by UPnP, Gateway by Telnet, Sensor by MQTT, Smartphone by MAC).
- **`test_credential_checker.py` (5 tests)**: Verifies non-destructive credential checks for HTTP Basic/Digest, open streaming access, and rejection of false positives.
- **`test_cve_matcher.py` (4 tests)**: Tests offline CVE database lookups and CVSS v3.1 scoring.
- **`test_vlan_scoper.py` (5 tests)**: Tests subnet-to-VLAN resolution and dynamic quarantine isolation triggers.
- **`test_bugfixes.py` (11 tests)**: Ensures resilience against ghost ARP entries, WAN subnet leakage, and form-login false positives.
- **`test_enhancements.py` (3 tests)**: Verifies presence monitoring and bandwidth metering snapshots.
- **`test_api_extensions.py` (7 tests)**: Tests REST API endpoints for scans, triage workflows, scope verification, and webhook notifications.
- **`test_integration.py` (1 test)**: End-to-end simulation from discovery through classification, CVE lookup, credential check, and quarantine recommendation.

---

## 6. Scaling with Mock Objects (`mock-object`)

To simulate enterprise or smart-home IoT environments with 10+ devices across multiple virtual VLANs without requiring physical hardware:

```powershell
# Deploy simulated IoT containers (Camera, SmartPlug, DVR, Gateway)
docker compose -f .\mock-object\docker-compose.template.yml up -d
```

Containers are assigned static IPs on `172.28.10.0/24` (Standard IoT Subnet), allowing `net-sec` to audit them as independent physical endpoints.
