# Camera Mock Object Subsystem (`mock-object`)

**Course**: IT6027 - Cybersecurity Policy and Governance  
**Subject**: System for Detecting Insecure IoT Devices within a Network  
**Version**: v0.2.0  

This module provides a specialized, profile-driven **Camera Emulation Engine** and **Fleet Manager** to simulate diverse IoT camera brands, authentication paradigms, and cybersecurity vulnerabilities on demand.

Per course project guidelines, physical devices (smartphones running IP Webcam) can be used alongside this module; these mock templates serve as a reproducible blueprint to scale the network to $N$ virtual camera endpoints for testing, automated audits, or demonstrations.

---

## 1. Supported Camera Profiles & Security Postures

The camera mock engine decouples emulation logic from device identity using declarative profiles in `mock-object/profiles/`:

| Profile ID | Brand & Model | Fingerprint Surfaces | Security Issues & Features | Authentication |
| :--- | :--- | :--- | :--- | :--- |
| `dlink_dcs932l` | D-Link DCS-932L | HTTP (8080), RTSP (554), mDNS, UPnP SSDP | Outdated firmware banner (`GoAhead-Webs/2.5`), vulnerable to CVE-2020-25078 | HTTP Basic (`admin:admin`, `123456`) |
| `hikvision_ds2cd` | Hikvision DS-2CD | HTTP (80), RTSP (554), mDNS, UPnP SSDP | Embedded web banner (`App-webs`), vulnerable to CVE-2021-36260 | HTTP Digest (`admin:admin`, `12345`) |
| `dahua_ipc` | Dahua DH-IPC | HTTP (80), RTSP (554), mDNS, UPnP SSDP | Proprietary banner (`Dahua-Webs`), hardcoded backdoor credentials (CVE-2016-10372) | HTTP Basic (`admin:7ujMko0vizxv`) |
| `ip_webcam` | Android IP Webcam | HTTP (8080), `/video`, mDNS | Smartphone emulation matching mobile devices used in course labs | HTTP Digest (`admin:admin`) |
| `open_access_cam` | Generic Surveillance | HTTP (8081), RTSP (554), `/videostream.cgi` | **Critical Security Violation**: Unshielded video stream (ETSI EN 303 645 & OWASP IoT Top 10) | None (**Open Access / No Password**) |
| `hardened_cam` | SecureCam ProSafe | HTTP (8443), RTSP (554), UPnP SSDP | **Compliant Baseline**: Patched firmware, strong non-default credentials | HTTP Digest (`admin:SecOps#2026!Camera`) |

---

## 2. Using the Camera Fleet Manager CLI (`fleet_manager.py`)

The `fleet_manager.py` utility provides a user-friendly CLI to spin up, monitor, and scale camera nodes locally with automated non-colliding port allocations:

### Inspect Available Profiles
```powershell
python mock-object/fleet_manager.py profiles
```

### Launch a Scaled Heterogeneous Camera Fleet
To start 4 diverse camera mock instances locally:
```powershell
python mock-object/fleet_manager.py start-fleet --count 4 --mixed
```
*Output*:
```
======================================================================
      Launching Camera Fleet (4 instances)
======================================================================
  [+] Spawned Node #1: dlink_dcs932l on HTTP:8080 / RTSP:8554 (PID: 1240)
  [+] Spawned Node #2: hikvision_ds2cd on HTTP:8081 / RTSP:8555 (PID: 1241)
  [+] Spawned Node #3: dahua_ipc on HTTP:8082 / RTSP:8556 (PID: 1242)
  [+] Spawned Node #4: open_access_cam on HTTP:8083 / RTSP:8557 (PID: 1243)
----------------------------------------------------------------------
[+] Successfully deployed 4 camera mock nodes.
```

### List Active Nodes
```powershell
python mock-object/fleet_manager.py list
```

### Terminate All Running Nodes
```powershell
python mock-object/fleet_manager.py stop
```

---

## 3. Running Individual Camera Instances with Custom Overrides

You can launch any profile standalone and override its parameters on the fly:

```powershell
# Launch D-Link camera with custom ports
python mock-object/engine/camera_server.py --profile dlink_dcs932l --http-port 8088 --rtsp-port 8554

# Launch Hikvision camera enforcing Open Access for compliance testing
python mock-object/engine/camera_server.py --profile hikvision_ds2cd --open-access --http-port 8089

# Launch Dahua camera with custom bind IP
python mock-object/engine/camera_server.py --profile dahua_ipc --ip 192.168.137.25 --http-port 80
```

---

## 4. Multi-VLAN Container Deployment (Docker Compose)

To spin up a containerized camera fleet across isolated virtual subnets (`172.28.10.0/24` for standard IoT and `172.28.99.0/24` for quarantine):

```powershell
# Deploy camera fleet template
docker compose -f .\mock-object\docker-compose.template.yml up -d
```

To generate a custom Docker Compose file with $N$ camera instances:
```powershell
python mock-object/fleet_manager.py generate-compose --count 5 --out custom-compose.yml
docker compose -f custom-compose.yml up -d
```
