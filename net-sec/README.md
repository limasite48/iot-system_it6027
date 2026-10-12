# IoT Insecure Device Detection & Governance Platform (`net-sec`)

**Course**: IT6027 - Cybersecurity Policy and Governance  
**Topic**: System for detecting insecure IoT devices within a network  
**Domain**: IoT Edge Networks, Embedded Endpoints & Smart Appliances  

---

## 1. System Overview & Three-Subsystem Architecture

The `net-sec` platform is an automated, non-intrusive security auditing and governance system specifically engineered for IoT edge environments (Smart TVs, Inverter ACs, Smart Fans, Smart Thermostats, IP Cameras, Smart Plugs, Sensors, and Smartphones).

In strict adherence to the project specification ([`project_draft.md`](../_antigravity/project_draft.md)) and engineering reference standards ([`ref_1.md`](../_antigravity/ref_1.md)), the platform is decomposed into three decoupled, interface-first subsystems:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ SUB-SYSTEM 1: Network & IoT Discovery (app/discovery/)                      │
│  - Host Discovery: Adaptive ARP sweep, ICMP probes, Windows SoftAP queries │
│  - Multicast Discovery: mDNS Zeroconf listener, UPnP SSDP M-SEARCH XML      │
│  - Deep Banner Grabber: HTTP/S, RTSP headers, Telnet, MQTT connect          │
│  - OUI Resolver: IEEE MAC database lookup with randomized private MAC logic │
├─────────────────────────────────────────────────────────────────────────────┤
│ SUB-SYSTEM 2: Vulnerability Assessment & Compliance (app/audit/)            │
│  - CPE 2.3 Normalizer: Standardizes hardware, firmware, services (NIST)    │
│  - Semantic Version Evaluator: Compares semver against CVE range bounds     │
│  - Multi-Feed CVE Manager: Correlates 19 real-world CVEs across 5 feeds     │
│  - Multi-Protocol Credential Checker: Audits Basic/Digest, Forms, RTSP, Open│
│  - Declarative Policy Engine: Validates YAML rules against JSON schema      │
│  - Contextual Prioritizer: CISA SSVC decision categories & VEX justifications│
│  - Auditor Triage Workflow: Human review lifecycle (PENDING->APPROVED/REJECT)│
├─────────────────────────────────────────────────────────────────────────────┤
│ SUB-SYSTEM 3: Platform, Orchestration & Governance (app/scoping/, web/)     │
│  - Scope Management Service: GET /api/scope/check enforcing boundary limits │
│  - Scan Orchestration Engine: 7-stage deterministic pipeline & scan history │
│  - Webhook Alert Dispatcher: Real-time alerting for Critical/High findings  │
│  - Interactive Dashboard: Visual Network Topology SVG, Device Inspector     │
│  - Academic Governance Report Generator: /api/report markdown export        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Scan Stage Pipeline Contract

All security audits execute through a deterministic 7-stage pipeline tracked via unique `scan_id`:

1. **`STAGE_1_SCOPE_VERIFICATION`**: Pre-flight boundary validation via `ScopeManager`. Prohibits scanning public WAN or unauthorized enterprise networks.
2. **`STAGE_2_MULTICAST_DISCOVERY`**: Concurrent passive and multicast discovery via mDNS Zeroconf (UDP 5353) and UPnP SSDP M-SEARCH (UDP 1900).
3. **`STAGE_3_HOST_ACTIVE_SWEEP`**: Active subnet sweeping assembling the target IP pool from ARP tables, SoftAP peer lists, and active port probes.
4. **`STAGE_4_DEEP_FINGERPRINTING`**: High-concurrency port scanning, banner grabbing, UPnP XML descriptor parsing, reverse DNS, and device classification.
5. **`STAGE_5_VULNERABILITY_AND_CREDENTIAL_AUDIT`**: NIST CPE 2.3 generation, SemVer CVE matching, dictionary credential auditing, and CISA SSVC / VEX contextual prioritization.
6. **`STAGE_6_POLICY_EVALUATION`**: Declarative YAML policy engine evaluation, VLAN scoping (VLAN 10 Operational vs VLAN 99 Quarantine), triage ledger recording, and alert dispatching.
7. **`STAGE_7_COMPLETED`**: Final cataloging, live presence synchronization, and scan history archival.

---

## 3. Declarative Policy Engine & Standards Compliance

The policy engine loads declarative YAML hardening rules from [`policies/iot_hardening_rules.yaml`](policies/iot_hardening_rules.yaml) and validates each rule against [`policies/policy_schema.json`](policies/policy_schema.json):

- **Rule POL-001**: Prohibition of publicly known default credentials (**ETSI EN 303 645 Requirement 5.1-1**).
- **Rule POL-002**: Prohibition of unauthenticated streaming & actuator open access (**ETSI EN 303 645 Requirement 5.1-2**).
- **Rule POL-003**: Prohibition of cleartext Telnet management (**NIST IR 8259A Section 2.1**).
- **Rule POL-004**: Mandate immediate VLAN 99 quarantine for Critical CVEs ($\text{CVSS} \ge 9.0$).
- **Rule POL-005**: Prohibition of unauthenticated MQTT telemetry brokers.
- **Rule POL-006**: Mandate TLS encryption on smart appliance control surfaces.

---

## 4. REST API & OpenAPI Documentation

FastAPI serves full OpenAPI 3.0 documentation with interactive Swagger UI and ReDoc:

- **Interactive Swagger UI**: `http://localhost:8000/docs`
- **ReDoc Documentation**: `http://localhost:8000/redoc`
- **Raw OpenAPI JSON**: `http://localhost:8000/openapi.json`

### Core API Endpoints

| Subsystem | HTTP Method | Endpoint | Description |
| :--- | :--- | :--- | :--- |
| **Subsystem 1** | `GET` | `/api/network/info` | Discovered edge subnets, active interfaces, SoftAP client list |
| **Subsystem 1** | `GET` | `/api/traffic` | Real-time isolated device Rx/Tx telemetry |
| **Subsystem 2** | `GET` | `/api/cve/database` | Summary of loaded CVE feeds and vulnerability definitions |
| **Subsystem 2** | `POST`| `/api/cve/sync` | Hot-reload vulnerability feeds and register custom CVEs |
| **Subsystem 2** | `POST`| `/api/cve/evaluate` | Ad-hoc contextual SSVC/VEX evaluation for a device dictionary |
| **Subsystem 2** | `GET` | `/api/findings` | Auditor triage finding ledger (filter by `PENDING`, `APPROVED`, `REJECTED`) |
| **Subsystem 2** | `POST`| `/api/findings/{id}/triage` | Auditor sign-off updating status, review notes, and auditor ID |
| **Subsystem 2** | `GET` | `/api/findings/stats` | Triage statistics (total, pending, approved, rejected) |
| **Subsystem 3** | `GET` | `/api/scope/check?cidr={cidr}` | Enforce authorized network boundaries (`allowed: bool`) |
| **Subsystem 3** | `GET` | `/api/scope/allowed` | List declared audit boundaries (Hotspot VLAN 100, Virtual IoT VLAN 10) |
| **Subsystem 3** | `POST`| `/api/scan` | Trigger asynchronous network audit scan |
| **Subsystem 3** | `GET` | `/api/scans` | Full scan history with execution stages and timestamps |
| **Subsystem 3** | `GET` | `/api/scans/{scan_id}` | Detailed results and device list for a specific audit scan |
| **Subsystem 3** | `GET` | `/api/config/webhook` | Webhook alert dispatcher configuration and delivery stats |
| **Subsystem 3** | `POST`| `/api/config/webhook` | Configure destination URL and enabled status for alerts |
| **Subsystem 3** | `GET` | `/api/report` | Export academic governance audit report (Markdown / HTML) |
| **Inventory**   | `GET` | `/api/devices` | Live catalog of discovered edge devices |
| **Inventory**   | `GET` | `/api/stats` | High-level risk metrics, quarantine counts, and device types |
| **Inventory**   | `GET` | `/api/alerts` | Real-time security alerts ledger |
| **Inventory**   | `GET` | `/api/scoping` | Device grouping by VLAN assignment (VLAN 10, 100, 99) |

---

## 5. Standalone Execution

### Web Dashboard & REST Service
Run the complete platform with FastAPI and the interactive dashboard:
```powershell
python run_scanner.py --web --host 0.0.0.0 --port 8000
```
Open **`http://localhost:8000`** in your browser.

### Headless CLI Scan
Run a one-shot security audit from the terminal without launching the web server:
```powershell
# Audit all authorized edge subnets (Hotspot + Virtual Mock IoT)
python run_scanner.py --cli --scan ALL

# Audit a specific edge subnet
python run_scanner.py --cli --scan 192.168.137.0/24
```

---

## 6. Automated Testing

Run the comprehensive test suite verifying discovery, CPE normalization, CVE matching, credential auditing, policy rules, and scoping:
```powershell
python -m pytest tests/ -v
```
All unit, integration, and security tests conform to pytest standards with 100% pass rates.
