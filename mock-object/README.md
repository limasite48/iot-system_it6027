# Mock Object Templates & Scaling Blueprints (`mock-object`)

This module provides standardized templates and Docker configurations to emulate vulnerable IoT devices on demand. Per project guidelines, physical devices (smartphones) are the primary targets; these templates serve as a reproducible blueprint to scale the network to 10+ virtual IoT devices whenever required for testing or demonstration.

---

## 1. Mock Templates Overview

| Template Name | Target Emulation | Fingerprint Surfaces | Vulnerability / Weakness | Default Credential |
| :--- | :--- | :--- | :--- | :--- |
| `camera-mock` | D-Link / Dahua IP Camera | HTTP (8080), RTSP (554), mDNS (`_camera._tcp`), UPnP SSDP | Outdated firmware banner (CVE-2020-25078) | `admin:admin`, `admin:123456` |
| `smartplug-mock` | TP-Link / WeMo Smart Plug | HTTP API (9999), UPnP SSDP, mDNS (`_smartplug._tcp`) | Unauthenticated control API (CVE-2019-14923) | None (No Auth) |
| `dvr-gateway-mock` | Xiongmai / BusyBox DVR Gateway | Telnet (23), HTTP (80) | Mirai botnet target, BusyBox banner (CVE-2017-8225) | `root:xc3511` |

---

## 2. How to Build and Launch Mock Devices

### Step 1: Build the Template Images
Navigate to the desired template folder and build:
```powershell
# Build camera mock
docker build -t iot-mock-camera:latest .\mock-object\templates\camera-mock\

# Build smartplug mock
docker build -t iot-mock-smartplug:latest .\mock-object\templates\smartplug-mock\

# Build DVR/gateway mock
docker build -t iot-mock-dvr:latest .\mock-object\templates\dvr-gateway-mock\
```

### Step 2: Launch via Docker Compose (Multi-VLAN Subnets)
Deploy the mock fleet across simulated VLANs:
```powershell
docker compose -f .\mock-object\docker-compose.template.yml up -d
```

### Step 3: Verifying Simulated Devices
Check running containers and assigned IP addresses:
```powershell
docker ps --filter "name=mock-"
```
Each container is provisioned with a distinct static IP on the virtual IoT subnet (`172.28.10.x`), ensuring `net-sec` scans individual endpoints without port collisions.

---

## 3. Scaling Up to N Devices
To scale up, duplicate service blocks in `docker-compose.template.yml` with incremented IP addresses (e.g. `mock-camera-02` at `172.28.10.25`, `mock-smartplug-02` at `172.28.10.26`).
