# Project Design Document: Insecure IoT Device Detection & Management Platform

**Course**: IT6027 - Cybersecurity Policy and Governance  
**Project Topic**: System for detecting insecure IoT devices within a network  
**Domain Specification**: Edge IoT Networks & Insecure Embedded Endpoints  

---

## 1. Domain Specification: IoT Networks vs. General Enterprise LANs

This project specifically targets **IoT (Internet of Things) edge networks and embedded endpoints**, strictly distinguishing itself from standard enterprise LAN vulnerability scanning (such as PC/Server scanning):

| Technical Dimension | General Enterprise LAN (ref_1.md) | IoT Edge Network (Our Project) |
| :--- | :--- | :--- |
| **Target Devices** | Windows/Linux PCs, active directory servers, enterprise routers. | Embedded Linux SoCs, microcontrollers, IP cameras, smart plugs, DVRs/NVRs, mobile phones acting as IoT sensors. |
| **Discovery Protocols** | ICMP sweep, standard ARP, NetBIOS, SNMP MIB tree. | **mDNS Zeroconf** (UDP 5353), **UPnP SSDP** (UDP 1900 M-SEARCH + XML descriptors), OUI vendor resolution, SoftAP client tables. |
| **Service Protocols** | SSH (22), SMB/CIFS (445), RDP (3389), Kerberos, LDAP. | **RTSP** (554), MJPEG video streaming (8080), **MQTT** (1883), proprietary IoT XOR control (9999), embedded web servers (**GoAhead-Webs**, **uc-httpd**, **App-webs**), Telnet (23). |
| **Password Testing** | Forbidden in general LAN scanning (*non-destructive*). | **Strictly Mandatory in IT6027 Syllabus**: Multi-protocol default credential auditing (HTTP Basic/Digest, Web Forms, RTSP, Telnet Mirai dictionary). |
| **CVE & CPE Standards** | Standard desktop software CPEs. | **IoT Hardware & Firmware CPE 2.3** (`cpe:2.3:o:dlink:dcs-932l_firmware:...`, `cpe:2.3:h:tp-link:hs100:...`). |
| **Policy & Hardening** | General OS benchmarks (CIS, SMBv1 disablement). | **IoT Baselines** (NIST IR 8259A, ETSI EN 303 645: no factory passwords, no unencrypted video/actuator control, VLAN 99 quarantine). |

---

## 2. System Architecture & Subsystem Decomposition

The platform is partitioned into two major layers:
1. **IoT Testbed Environment (Target of Evaluation)**:
   - `net-infrastructure`: Physical edge SoftAP Wi-Fi network (`192.168.137.0/24`) broadcasting from laptop to smartphones.
   - `net-core`: Mosquitto MQTT message broker (`1883`) and central HTTP telemetry registry (`5000`).
   - `mock-object`: Docker-based multi-VLAN virtual IoT devices (`172.28.10.0/24` for standard IoT, `172.28.99.0/24` for quarantine).
2. **Security Auditing & Governance Platform (`net-sec`)**:
   - Organized into three technical subsystems matching high-scoring engineering rigor:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ SUB-SYSTEM 1: Network & IoT Discovery (app/discovery/)                      │
│  - Host Discovery: ARP sweeps, ICMP probes, Windows SoftAP client query     │
│  - Multicast Discovery: mDNS Zeroconf listener, UPnP SSDP M-SEARCH XML      │
│  - Banner Grabber: HTTP/S, RTSP live stream headers, Telnet, MQTT connect   │
│  - OUI Resolver: IEEE MAC database lookup with randomized private MAC logic │
├─────────────────────────────────────────────────────────────────────────────┤
│ SUB-SYSTEM 2: Vulnerability Assessment & Compliance (app/audit/)            │
│  - CPE 2.3 Normalizer: Standardizes hardware, firmware, and services        │
│  - Semantic Version Evaluator: Compares semver against CVE range bounds     │
│  - CVE Matching Engine: Correlates CPEs & banners against IoT CVE database  │
│  - Default Credential Checker: Audits HTTP Basic/Digest, Forms, RTSP, Telnet│
│  - Declarative Policy Engine: Evaluates YAML rules (policies/hardening.yaml)│
│  - Auditor Triage Workflow: Finding lifecycle (PENDING -> APPROVED/REJECTED)│
├─────────────────────────────────────────────────────────────────────────────┤
│ SUB-SYSTEM 3: Platform, Orchestration & Governance (app/scoping/, web/)     │
│  - Scope Management Service: GET /api/scope/check enforcing boundary limits │
│  - Scan Orchestration Engine: Stages, scan_id, execution history            │
│  - Webhook Alert Dispatcher: Real-time alerting for Critical/High findings  │
│  - Interactive Dashboard: Visual Network Topology SVG, Device Inspector     │
│  - Academic Governance Report Generator: /api/report markdown export        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Interface & Event Contracts

- **Scope Check Contract**:
  - `GET /api/scope/check?cidr={cidr}` $\rightarrow$ `{ allowed: bool, cidr: str, vlan_name: str, reason: str }`
- **Scan Stage Pipeline**:
  - `STAGE_1_SCOPE_VERIFICATION`
  - `STAGE_2_MULTICAST_DISCOVERY`
  - `STAGE_3_HOST_ACTIVE_SWEEP`
  - `STAGE_4_DEEP_FINGERPRINTING`
  - `STAGE_5_VULNERABILITY_AND_CREDENTIAL_AUDIT`
  - `STAGE_6_POLICY_EVALUATION`
  - `STAGE_7_COMPLETED`
- **Auditor Triage Contract**:
  - `POST /api/findings/{id}/triage` $\rightarrow$ `{ status: "APPROVED" | "REJECTED", auditor_notes: str, reviewer: str }`
- **CPE 2.3 Formatting**:
  - `cpe:2.3:[part]:[vendor]:[product]:[version]:[update]:[edition]:*:*:*:*:*`
  - Parts: `h` (hardware device), `o` (operating system / firmware), `a` (application).

---

## 4. Definition of Done (DoD)

1. **End-to-End Audit**: Successfully scan physical SoftAP (`192.168.137.0/24`) and virtual IoT VLANs (`172.28.10.0/24`), discovering smartphones and mock IoT devices without ghost ARP leases.
2. **CPE Normalization & CVE Correlation**: Convert detected banners into valid CPE 2.3 URIs and match corresponding CVEs with semantic version verification.
3. **Mandatory Credential Auditing**: Detect unauthenticated open video streams and default passwords (e.g. `admin:admin`, `root:xc3511`).
4. **Declarative Governance Enforcement**: Evaluate devices against declarative YAML hardening rules and mandate VLAN 99 quarantine for failing endpoints.
5. **Auditor Verification**: Allow human auditor sign-off (`APPROVED` / `REJECTED`) before generating the final governance report.
6. **Containerization & Automated Testing**: Root `docker-compose.yml` to spin up mock IoT devices and testbed; 100% test pass rate across the automated test suite.