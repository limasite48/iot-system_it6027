# Docker Container Deployment & Verification Guide
## Course: IT6027 - Cyber Security Policy and Governance
### Academic Project: Automated IoT Insecure Device Detection & Governance Platform

This document provides complete instructions for executing, evaluating, and packaging the system using Docker containers, fulfilling the course requirement:
> *"The system must be functional. You are required to submit the source code and the virtual machine or Docker container."* (Teacher Note 1)

---

## 1. Cross-Platform Architecture & Compatibility

The platform is engineered to run seamlessly across all major operating systems:
- **macOS**: Fully compatible with both **Apple Silicon (M1/M2/M3/M4)** and **Intel x86_64** processors. Docker Desktop or Colima runs the Linux VM kernel natively, executing the multi-subnet bridge networks inside Docker's virtualization layer.
- **Windows**: Fully compatible with **Windows 10/11** via Docker Desktop with WSL2 backend.
- **Linux**: Fully compatible with native Docker Engine and Docker Compose v2.

### Multi-Architecture Container Images
All base images used in the stack provide official multi-arch support (`linux/amd64` and `linux/arm64`):
1. **Auditor & Web Platform (`iot-net-sec:latest`)**: Based on `python:3.11-slim` (Debian-based, compiled for AMD64/ARM64).
2. **Mock IoT Devices (`iot-mock-camera:latest`)**: Based on `python:3.11-alpine` (lightweight, multi-arch).
3. **Telemetry Broker (`iot-net-core-mqtt`)**: Based on official `eclipse-mosquitto:2.0` (multi-arch).

---

## 2. Container Topology Overview

```
                      +------------------------------------------+
                      |         Host Machine (Mac / PC)          |
                      |  Browser UI: http://localhost:8000       |
                      |  Broker Port: localhost:1883             |
                      +--------------------+---------------------+
                                           |
    ============================= Docker Bridge Networks =============================
    
    [ VLAN 10 - Operational Subnet: 172.28.10.0/24 ]
      |
      +---> [net-sec-platform]       (172.28.10.90)  <-- Scanner Engine, Web UI, SQLite DB
      +---> [net-core-mqtt]          (172.28.10.10)  <-- Mosquitto MQTT Broker (1883)
      +---> [mock-device-01]         (172.28.10.20)  <-- D-Link Camera (Default Creds, CVSS 9.8)
      +---> [mock-device-02]         (172.28.10.21)  <-- Sony Bravia Smart TV (Compliant Baseline)
      +---> [mock-device-03]         (172.28.10.22)  <-- Daikin Smart AC (Unauthenticated Admin)
      +---> [mock-device-04]         (172.28.10.23)  <-- ProSafe IP Camera (Hardened Baseline)

    [ VLAN 99 - Quarantine Subnet: 172.28.99.0/24 ]
      |
      +---> [net-sec-platform]       (172.28.99.90)  <-- Dual-homed Gateway Interface
      +---> [mock-device-quarantine] (172.28.99.20)  <-- Isolated Compromised Node
```

---

## 3. Quick Start Instructions

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (macOS, Windows, or Linux) with Docker Compose v2+.

### Option A: One-Click Startup Script

**On macOS or Linux:**
```bash
chmod +x docker-start.sh docker-stop.sh
./docker-start.sh
```

**On Windows:**
Double-click `docker-start.bat` or run in terminal:
```cmd
docker-start.bat
```

### Option B: Direct Docker Compose Commands
```bash
# Build and launch all 7 containers in detached mode
docker compose up --build -d

# Verify all services are running (State: Up)
docker compose ps
```

---

## 4. Verification & Evaluation Procedures

Once launched, verify the system functionality using the following interfaces:

### 1. Web Governance Dashboard
Open your web browser and navigate to:
```
http://localhost:8000
```
- Real-time audit metrics, discovered devices, open ports, vulnerability CVE scores, and policy compliance violations will populate dynamically.
- OpenAPI specification and interactive Swagger UI: `http://localhost:8000/docs`

### 2. Relational Database Health & Statistics
Query the database persistence endpoint:
```bash
curl http://localhost:8000/api/db/stats
```
Expected output showing persisted tables and records:
```json
{
  "db_path": "/app/data/iot_security.db",
  "file_size_bytes": 188416,
  "scans_count": 6,
  "devices_count": 14,
  "ports_count": 19,
  "cve_findings_count": 18,
  "triage_records_count": 44,
  "alerts_count": 40
}
```
The database is volume-mounted to `./net-sec/data/iot_security.db` on your host machine, ensuring audit records survive container teardown and restarts.

### 3. Triggering Active Security Audits
Trigger an on-demand active scan of all network subnets via the REST API:
```bash
curl -X POST http://localhost:8000/api/scan -H "Content-Type: application/json" -d "{}"
```
Verify scan status:
```bash
curl http://localhost:8000/api/status
```

### 4. Running the Benchmark & Performance Harness
To reproduce the performance metrics (latency, device throughput, memory footprint):
```bash
cd net-sec
python benchmark_audit.py --devices 4 --count 3
```

---

## 5. Submission & Offline Packaging (Teacher Note 1)

Depending on the instructor's submission portal requirements:

### Submission Format 1: Source Code + Dockerfile (Standard)
Submit the compressed repository folder (`.zip` or Git repository). The recipient only needs to execute:
```bash
docker compose up --build -d
```

### Submission Format 2: Standalone Offline Container Archive (`.tar.gz`)
If submitting to an air-gapped machine without internet access for building images:

**1. Export images on the development machine:**
- On macOS/Linux: Run `./docker-export.sh` (produces `iot-security-images.tar.gz`)
- On Windows: Run `docker-export.bat` (produces `iot-security-images.tar`)

**2. Import and run on the evaluator's machine:**
```bash
# Load images into local Docker daemon
docker load < iot-security-images.tar.gz

# Start the stack using pre-loaded images
docker compose up -d
```

---

## 6. Stopping and Cleanup

To gracefully stop and remove containers while preserving persisted database records:
```bash
# On macOS / Linux
./docker-stop.sh

# On Windows
docker-stop.bat

# Or directly:
docker compose down
```
All persistent audit history and triage decisions will remain intact inside `./net-sec/data/iot_security.db`.
