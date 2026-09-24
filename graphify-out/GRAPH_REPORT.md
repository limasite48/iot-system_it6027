# Graph Report - iot-system  (2026-09-24)

## Corpus Check
- Corpus is ~14,648 words - fits in a single context window. You may not need a graph.

## Summary
- 255 nodes · 442 edges · 16 communities (13 shown, 3 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 5 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Module Group 0
- Module Group 1
- Module Group 2
- Module Group 3
- Module Group 4
- Module Group 5
- Module Group 6
- Module Group 7
- Module Group 8
- Module Group 9
- Module Group 10
- Module Group 11
- Module Group 12
- Module Group 13

## God Nodes (most connected - your core abstractions)
1. `SecurityScannerEngine` - 16 edges
2. `classify_device()` - 12 edges
3. `test_device_credentials()` - 10 edges
4. `match_cves_for_device()` - 10 edges
5. `inspect_all_banners()` - 9 edges
6. `TrafficMeter` - 9 edges
7. `evaluate_scoping_policy()` - 9 edges
8. `IoTGatewayHTTPHandler` - 8 edges
9. `MDNSIotListener` - 8 edges
10. `resolve_vlan_for_ip()` - 8 edges

## Surprising Connections (you probably didn't know these)
- `test_load_default_credentials()` --calls--> `load_default_credentials()`  [EXTRACTED]
  net-sec/tests/test_credential_checker.py → net-sec/app/audit/credential_checker.py
- `test_open_access_no_password_detected()` --calls--> `test_device_credentials()`  [EXTRACTED]
  net-sec/tests/test_enhancements.py → net-sec/app/audit/credential_checker.py
- `test_cve_database_loaded()` --calls--> `load_cve_database()`  [EXTRACTED]
  net-sec/tests/test_cve_matcher.py → net-sec/app/audit/cve_matcher.py
- `test_camera_cve_matching()` --calls--> `match_cves_for_device()`  [EXTRACTED]
  net-sec/tests/test_cve_matcher.py → net-sec/app/audit/cve_matcher.py
- `test_clean_device_no_false_positives()` --calls--> `match_cves_for_device()`  [EXTRACTED]
  net-sec/tests/test_cve_matcher.py → net-sec/app/audit/cve_matcher.py

## Import Cycles
- None detected.

## Communities (16 total, 3 thin omitted)

### Community 0 - "Module Group 0"
Cohesion: 0.07
Nodes (24): base64, http_server, json, Simulated Legacy IP Camera (mock-object template) Emulates a D-Link DCS-932L IP…, Answers UPnP SSDP M-SEARCH requests., run_ssdp_responder(), DVRWebHandler, handle_telnet_client() (+16 more)

### Community 1 - "Module Group 1"
Cohesion: 0.09
Nodes (22): load_default_credentials(), Any, Default Credential Auditing Engine (net-sec) Non-destructively tests discovered…, Audit all open services on an IoT device against the predefined dictionary., Test HTTP Basic / Digest authentication and detect unauthenticated open access., Test Telnet authentication against default credentials (e.g. Mirai dictionary)., test_device_credentials(), test_http_auth() (+14 more)

### Community 2 - "Module Group 2"
Cohesion: 0.11
Nodes (17): importlib_util, Any, Run full network discovery, audit, and scoping pipeline., Robust multi-layer presence check: localhost bypass, TCP probe on known ports,…, Single check cycle for joining and leaving devices., Start recurring background watcher for device join/leave events., Compute system-wide dashboard metrics including traffic and online states., Read system ARP table to find known IPs and MAC addresses. (+9 more)

### Community 3 - "Module Group 3"
Cohesion: 0.11
Nodes (23): BackgroundTasks, BaseModel, fastapi, fastapi_middleware_cors, fastapi_responses, fastapi_staticfiles, get, generate_markdown_report() (+15 more)

### Community 4 - "Module Group 4"
Cohesion: 0.13
Nodes (18): get_arp_neighbors(), get_local_interfaces(), main(), ping_host(), Retrieve active IPv4 addresses on the host system., IoT Network Diagnostics Utility (net-infrastructure) Detects active network…, Extract ARP entries to find connected physical devices., Ping an IP address to test connectivity. (+10 more)

### Community 5 - "Module Group 5"
Cohesion: 0.13
Nodes (12): datetime, IoTGatewayHTTPHandler, BaseHTTPRequestHandler, Optional background listener for Mosquitto MQTT broker., IoT Core Gateway & Telemetry Registry (net-core) Provides central IoT device…, Update or register an IoT device with incoming telemetry., HTTP REST handler for device telemetry and web status., register_telemetry() (+4 more)

### Community 6 - "Module Group 6"
Cohesion: 0.21
Nodes (14): ipaddress, evaluate_scoping_policy(), group_devices_by_vlan(), Any, VLAN Scoping & Isolation Policy Engine (net-sec bonus requirement) Groups…, Map an IP address to its corresponding VLAN scope., Evaluate device risk and determine VLAN isolation / quarantine actions., Group inventory devices by their VLAN scope and compute aggregate statistics. (+6 more)

### Community 7 - "Module Group 7"
Cohesion: 0.22
Nodes (8): discover_mdns_devices(), MDNSIotListener, Any, mDNS / Zeroconf Discovery Listener (net-sec) Discovers IoT devices advertising…, Scan the local network for mDNS IoT services during timeout_seconds., ServiceListener, time, Zeroconf

### Community 8 - "Module Group 8"
Cohesion: 0.23
Nodes (12): grab_http_banner(), grab_mqtt_banner(), grab_rtsp_banner(), grab_telnet_banner(), inspect_all_banners(), Any, IoT Service Banner Grabber (net-sec) Interrogates open IoT ports to extract…, Inspect all open ports on a host and collect comprehensive banners. (+4 more)

### Community 9 - "Module Group 9"
Cohesion: 0.27
Nodes (10): classify_device(), Any, Device Type Classifier (net-sec) Categorizes devices into functional IoT…, Determine the high-level device category. Returns: 'IP Camera', 'Smart Plug',…, test_classify_camera_by_banner(), test_classify_camera_by_rtsp_port(), test_classify_gateway_by_telnet(), test_classify_sensor_by_mqtt() (+2 more)

### Community 10 - "Module Group 10"
Cohesion: 0.27
Nodes (9): argparse, asyncio, main(), print_banner(), IoT Insecure Device Detection & Management Platform - CLI & Server Runner (net-…, run_cli_scan(), run_web_server(), os (+1 more)

### Community 11 - "Module Group 11"
Cohesion: 0.22
Nodes (9): httpx, discover_upnp_devices(), parse_ssdp_response(), parse_upnp_xml(), Any, UPnP / SSDP Discovery Scanner (net-sec) Discovers IoT devices via SSDP M-SEARCH…, Extract device metadata from UPnP XML root., Broadcasts SSDP M-SEARCH and collects device descriptors. (+1 more)

### Community 12 - "Module Group 12"
Cohesion: 0.33
Nodes (9): load_cve_database(), match_cves_for_device(), Any, Firmware & CVE Matching Engine (net-sec) Matches discovered device banners,…, Correlate device metadata against the CVE database. device_info can contain: -…, test_camera_cve_matching(), test_clean_device_no_false_positives(), test_cve_database_loaded() (+1 more)

## Knowledge Gaps
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `SecurityScannerEngine` connect `Module Group 2` to `Module Group 1`, `Module Group 10`, `Module Group 3`, `Module Group 4`?**
  _High betweenness centrality (0.104) - this node is a cross-community bridge._
- **Why does `TrafficMeter` connect `Module Group 1` to `Module Group 4`?**
  _High betweenness centrality (0.076) - this node is a cross-community bridge._
- **Why does `classify_device()` connect `Module Group 9` to `Module Group 2`, `Module Group 4`?**
  _High betweenness centrality (0.058) - this node is a cross-community bridge._
- **Should `Module Group 0` be split into smaller, more focused modules?**
  _Cohesion score 0.07308377896613191 - nodes in this community are weakly interconnected._
- **Should `Module Group 1` be split into smaller, more focused modules?**
  _Cohesion score 0.08522727272727272 - nodes in this community are weakly interconnected._
- **Should `Module Group 2` be split into smaller, more focused modules?**
  _Cohesion score 0.1076923076923077 - nodes in this community are weakly interconnected._
- **Should `Module Group 3` be split into smaller, more focused modules?**
  _Cohesion score 0.11231884057971014 - nodes in this community are weakly interconnected._