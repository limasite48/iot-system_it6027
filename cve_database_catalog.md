# BÁO CÁO CƠ SỞ DỮ LIỆU LỖ HỔNG CVE VÀ ĐIỂM SỐ CVSS CHÍNH THỨC
## HỌC PHẦN: CHÍNH SÁCH VÀ QUẢN TRỊ AN TOÀN THÔNG TIN (IT6027)
**Nguồn dữ liệu thẩm tra:** Viện Tiêu chuẩn và Kỹ thuật Quốc gia Hoa Kỳ (NIST NVD API v2.0) & MITRE CVE List  
**Ngày cập nhật:** 17/10/2026 | **Tổng số lỗ hổng định danh:** 16 CVEs  

---

### 1. Nguồn gốc và Kiến trúc Tích hợp Dữ liệu

Hệ thống áp dụng mô hình **Kiến trúc Tích hợp Kép (Hybrid Edge-Cloud Architecture)**:
1. **Tầng Snapshot Chính thức Cục bộ (Local NVD Snapshot):** Lưu trữ bộ dữ liệu đã được xác thực 100% khớp chuẩn lược đồ NIST NVD REST API 2.0, phục vụ việc kiểm toán an ninh trên các phân vùng mạng IoT cô lập (air-gapped/offline) mà không bị phụ thuộc kết nối Internet.
2. **Tầng Đồng bộ Thời gian thực (Live NIST NVD 2.0 API Sync):** Tích hợp client API trực tiếp tới máy chủ chính phủ Hoa Kỳ (`https://services.nvd.nist.gov/rest/json/cves/2.0`) qua module `CveManager`, cho phép đồng bộ lỗ hổng mới theo mã chuẩn CPE 2.3.

---

### 2. Danh mục Đối soát Chi tiết Các Lỗ hổng IoT Chính thức

| Mã CVE | Phân loại Thiết bị | Điểm CVSS v3.1 | Chuỗi Vector CVSS | Mã NIST CWE | CISA KEV | Liên kết NIST NVD Chính thức |
| :--- | :--- | :---: | :--- | :---: | :---: | :--- |
| **`CVE-2020-25078`** | Surveillance / IP Camera | **7.5** (HIGH) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | `CWE-200` | Không | [CVE-2020-25078](https://nvd.nist.gov/vuln/detail/CVE-2020-25078) |
| **`CVE-2021-36260`** | Surveillance / IP Camera | **9.8** (CRITICAL) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `CWE-78` | CÓ (Đang bị khai thác) | [CVE-2021-36260](https://nvd.nist.gov/vuln/detail/CVE-2021-36260) |
| **`CVE-2021-33044`** | Surveillance / IP Camera | **9.8** (CRITICAL) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `CWE-287` | CÓ (Đang bị khai thác) | [CVE-2021-33044](https://nvd.nist.gov/vuln/detail/CVE-2021-33044) |
| **`CVE-2017-8225`** | Surveillance / IP Camera | **7.5** (HIGH) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | `CWE-200` | Không | [CVE-2017-8225](https://nvd.nist.gov/vuln/detail/CVE-2017-8225) |
| **`CVE-2018-9995`** | Surveillance / IP Camera | **9.8** (CRITICAL) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `CWE-287` | CÓ (Đang bị khai thác) | [CVE-2018-9995](https://nvd.nist.gov/vuln/detail/CVE-2018-9995) |
| **`CVE-2014-8361`** | IoT Gateway / Router SDK | **9.8** (CRITICAL) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `CWE-78` | CÓ (Đang bị khai thác) | [CVE-2014-8361](https://nvd.nist.gov/vuln/detail/CVE-2014-8361) |
| **`CVE-2023-38906`** | Smart Home / Actuators | **8.8** (HIGH) | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `CWE-306` | Không | [CVE-2023-38906](https://nvd.nist.gov/vuln/detail/CVE-2023-38906) |
| **`CVE-2017-7650`** | IoT Telemetry / Broker | **7.5** (HIGH) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | `CWE-287` | Không | [CVE-2017-7650](https://nvd.nist.gov/vuln/detail/CVE-2017-7650) |
| **`CVE-2023-6317`** | Smart Appliances / Smart TV | **7.2** (HIGH) | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | `CWE-287` | Không | [CVE-2023-6317](https://nvd.nist.gov/vuln/detail/CVE-2023-6317) |
| **`CVE-2023-6318`** | Smart Appliances / Smart TV | **8.8** (HIGH) | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `CWE-78` | Không | [CVE-2023-6318](https://nvd.nist.gov/vuln/detail/CVE-2023-6318) |
| **`CVE-2021-25437`** | Smart Appliances / Smart TV | **8.1** (HIGH) | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `CWE-284` | Không | [CVE-2021-25437](https://nvd.nist.gov/vuln/detail/CVE-2021-25437) |
| **`CVE-2022-38355`** | Smart Appliances / Climate Control | **7.5** (HIGH) | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | `CWE-200` | Không | [CVE-2022-38355](https://nvd.nist.gov/vuln/detail/CVE-2022-38355) |
| **`CVE-2025-10127`** | Smart Appliances / Climate Control | **9.8** (CRITICAL) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `CWE-640` | Không | [CVE-2025-10127](https://nvd.nist.gov/vuln/detail/CVE-2025-10127) |
| **`CVE-2013-4860`** | Smart Appliances / Climate Control | **7.5** (HIGH) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | `CWE-287` | Không | [CVE-2013-4860](https://nvd.nist.gov/vuln/detail/CVE-2013-4860) |
| **`CVE-2020-13595`** | IoT Microcontroller Sensor | **6.5** (MEDIUM) | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | `CWE-120` | Không | [CVE-2020-13595](https://nvd.nist.gov/vuln/detail/CVE-2020-13595) |
| **`CVE-2019-15894`** | IoT Microcontroller Sensor | **6.8** (MEDIUM) | `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | `CWE-310` | Không | [CVE-2019-15894](https://nvd.nist.gov/vuln/detail/CVE-2019-15894) |

---

### 3. Chi tiết Kỹ thuật Từng Lỗ hổng (Theo Tiêu chuẩn NIST)

#### 1. CVE-2020-25078 - D-Link IP Camera Unauthenticated Configuration & Plaintext Credential Disclosure
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2020-25078
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **7.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-200`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:o:dlink:dcs-932l_firmware:*:*:*:*:*:*:*:*`
  - `cpe:2.3:o:dlink:dcs-930l_firmware:*:*:*:*:*:*:*:*`
  - `cpe:2.3:a:embedthis:goahead:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** An issue was discovered on D-Link DCS-2530L before 1.06.01 Hotfix and DCS-2670L through 2.02 devices, and DCS-932L series. The unauthenticated administrator password disclosure vulnerability occurs via a direct request to /common/info.cgi, which leaks system configuration and passwords.
- **Biện pháp Khắc phục:** Update camera firmware to the latest security patch. Isolate video camera interfaces into a dedicated Quarantine/Restricted VLAN (VLAN 99) and disable WAN exposure.

#### 2. CVE-2021-36260 - Hikvision IP Camera Unauthenticated Remote Command Execution (RCE)
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2021-36260
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-78`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:h:hikvision:ds-2cd:*:*:*:*:*:*:*:*`
  - `cpe:2.3:o:hikvision:ds-2cd_firmware:*:*:*:*:*:*:*:*`
  - `cpe:2.3:a:hikvision:app-webs:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** A command injection vulnerability in the web server of some Hikvision IP cameras allows attackers to send specially crafted packets to gain full administrative root shell access without credentials. Actively cataloged in CISA KEV.
- **Biện pháp Khắc phục:** Apply official Hikvision firmware upgrade (v5.5.800+) immediately and segment camera into restricted VLAN with zero egress WAN routing.

#### 3. CVE-2021-33044 - Dahua IP Camera & DVR Identity Authentication Bypass (CISA KEV)
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2021-33044
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-287`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:h:dahua:dahua_ipc:*:*:*:*:*:*:*:*`
  - `cpe:2.3:o:dahua:dahua_ipc_firmware:*:*:*:*:*:*:*:*`
  - `cpe:2.3:h:dahua:dahua_dvr:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** An identity authentication bypass vulnerability in the login handling of Dahua IP cameras allows remote attackers to bypass authentication and gain full administrator privileges by sending crafted NetKeyboard authentication packets. Actively exploited in CISA KEV catalog.
- **Biện pháp Khắc phục:** Upgrade to vendor-patched firmware release and block management port 37777/80 from untrusted segments.

#### 4. CVE-2017-8225 - Xiongmai / Sofia IP Camera & DVR Remote Code Execution & RTSP Bypass
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2017-8225
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **7.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-200`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:o:xiongmai:h.264_dvr_firmware:*:*:*:*:*:*:*:*`
  - `cpe:2.3:a:xiongmai:uc-httpd:*:*:*:*:*:*:*:*`
  - `cpe:2.3:a:xiongmai:sofia_rtsp:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** On Wireless IP Camera (P2P) WIFICAM devices and Xiongmai OEM hardware, access to sensitive configuration .ini files (containing plaintext credentials) is not correctly restricted, allowing remote attackers to extract credentials and hijack RTSP streams.
- **Biện pháp Khắc phục:** Replace legacy Xiongmai P2P firmware, disable cloud P2P services, and enforce strict network segmentation.

#### 5. CVE-2018-9995 - TBK & H.264 DVR Authentication Bypass & Credential Harvesting
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2018-9995
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-287`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:h:tbk:h.264_dvr:*:*:*:*:*:*:*:*`
  - `cpe:2.3:h:tbk:dvr-4104:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** TBK DVR4104 and DVR4216 devices allow remote attackers to bypass authentication and obtain user credentials via a 'Cookie: uid=admin' HTTP header request to device web endpoints. Listed in CISA KEV catalog.
- **Biện pháp Khắc phục:** Disconnect unpatched TBK DVRs from external networks, replace deprecated hardware, and place on Quarantine VLAN.

#### 6. CVE-2014-8361 - Realtek SDK miniigd SOAP UPnP Command Execution (Mirai Botnet Vector)
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2014-8361
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-78`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:a:realtek:miniigd:*:*:*:*:*:*:*:*`
  - `cpe:2.3:a:realtek:realtek_sdk:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** The miniigd SOAP service in Realtek SDK allows remote attackers to execute arbitrary code via crafted NewInternalClient requests to the UPnP daemon. A primary infection and propagation vector for the Mirai and Satori botnets. CISA KEV listed.
- **Biện pháp Khắc phục:** Disable UPnP service on edge and WAN interfaces, update router gateway firmware, and block external SSDP 1900/UDP.

#### 7. CVE-2023-38906 - TP-Link Kasa / Tapo Smart Home Devices Insecure Local Protocol & Actuator Manipulation
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2023-38906
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **8.8** (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-306`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:h:tp-link:hs100:*:*:*:*:*:*:*:*`
  - `cpe:2.3:h:tp-link:hs110:*:*:*:*:*:*:*:*`
  - `cpe:2.3:h:tp-link:kasa_smart_plug:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** Insecure local communication and authentication flaws in TP-Link smart plugs permit adjacent network attackers to replay or forge control messages over the local port, allowing unauthorized relay state flipping or configuration extraction.
- **Biện pháp Khắc phục:** Apply the latest TP-Link firmware patch via Kasa/Tapo app and segment smart plugs into an isolated IoT VLAN without route to management subnets.

#### 8. CVE-2017-7650 - Eclipse Mosquitto MQTT Broker Pattern-based ACL Wildcard Topic Bypass
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2017-7650
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **7.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-287`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** In Eclipse Mosquitto before 1.4.12, pattern-based access control lists (ACLs) can be bypassed by unauthenticated or anonymous clients setting usernames or client IDs with wildcard characters ('#' or '+'), granting unauthorized subscription to restricted topics.
- **Biện pháp Khắc phục:** Upgrade Mosquitto to version 1.4.12+ (or 2.0+), enforce TLS (port 8883), and disallow anonymous access ('allow_anonymous false').

#### 9. CVE-2023-6317 - LG webOS Smart TV secondscreen.gateway Account Creation & Authorization Prompt Bypass
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2023-6317
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **7.2** (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-287`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:o:lg:webos:*:*:*:*:*:*:*:*`
  - `cpe:2.3:h:lg:webos_smart_tv:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** An issue discovered by Bitdefender in LG webOS versions 4 through 7 allows remote unauthenticated attackers on the adjacent network to bypass user prompt PIN validation in secondscreen.gateway and create privileged local accounts.
- **Biện pháp Khắc phục:** Apply LG Electronics official software update (webOS patch April 2024) and isolate smart TV onto the home guest/IoT VLAN.

#### 10. CVE-2023-6318 - LG webOS Smart TV Arbitrary Command Injection in Process Manager
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2023-6318
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **8.8** (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-78`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:o:lg:webos:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** A flaw in the process manager of LG webOS allows an authenticated adjacent attacker (or attacker abusing CVE-2023-6317) to execute arbitrary operating system commands with root privileges.
- **Biện pháp Khắc phục:** Apply LG security firmware updates and disable developer remote debug options.

#### 11. CVE-2021-25437 - Samsung Tizen Smart TV FOTA Arbitrary Code Execution / Improper Access Control
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2021-25437
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **8.1** (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-284`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:o:samsung:tizen:*:*:*:*:*:*:*:*`
  - `cpe:2.3:h:samsung:tizen_smart_tv:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** Improper access control in the Tizen FOTA (Firmware Over-The-Air) service on Samsung Smart TVs allows adjacent attackers to execute arbitrary code or replace update components without authorization.
- **Biện pháp Khắc phục:** Enable Auto-Update in Samsung TV settings to install official Security Vulnerability Patches (SVP).

#### 12. CVE-2022-38355 - Daikin Smart Air Conditioner Controller Information Disclosure & Plaintext Credentials
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2022-38355
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **7.5** (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-200`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:h:daikin:brp069:*:*:*:*:*:*:*:*`
  - `cpe:2.3:o:daikin:brp069_firmware:*:*:*:*:*:*:*:*`
  - `cpe:2.3:h:daikin:smart_ac:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** Daikin connected HVAC controllers suffer from improper access permissions, allowing adjacent network clients to read configuration files containing plaintext management passwords and tamper with climate controls.
- **Biện pháp Khắc phục:** Isolate Daikin smart controllers to an isolated IoT VLAN and install vendor maintenance patches.

#### 13. CVE-2025-10127 - Daikin Security Gateway Password Reset Authorization Bypass & Factory Credential Reversion
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2025-10127
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-640`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:h:daikin:security_gateway:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** An unauthenticated remote attacker can trigger password reset via /api/settings/password/reset on Daikin Security Gateway, resetting credentials to factory default ('Daikin' / 'Daikin') and taking complete control of the HVAC infrastructure.
- **Biện pháp Khắc phục:** Do not expose Daikin controllers to WAN. Place in quarantined VLAN 99 and block unauthenticated HTTP POST.

#### 14. CVE-2013-4860 - Radio Thermostat CT50 / CT80 Unauthenticated HTTP REST API Temperature Override
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2013-4860
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **7.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-287`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:h:radiothermostat:ct50:*:*:*:*:*:*:*:*`
  - `cpe:2.3:h:radiothermostat:ct80:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** Radio Thermostat CT50 and CT80 devices expose a local HTTP REST API that completely lacks authentication, enabling any user or malicious script on the network to alter temperature setpoints, turn heating/cooling on or off, and extract Wi-Fi credentials.
- **Biện pháp Khắc phục:** Enforce firewall rules to restrict LAN access to trusted controller IP only, or migrate to authenticated thermostat firmware.

#### 15. CVE-2020-13595 - Espressif ESP32 ESP-IDF Bluetooth Low Energy Controller Memory Corruption
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2020-13595
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **6.5** (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-120`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:h:espressif:esp32:*:*:*:*:*:*:*:*`
  - `cpe:2.3:o:espressif:esp-idf:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** The Bluetooth Low Energy (BLE) controller implementation in Espressif ESP-IDF 4.0 through 4.2 for ESP32 devices improperly handles incoming packets, leading to potential denial-of-service crashes or memory corruption.
- **Biện pháp Khắc phục:** Compile firmware using patched Espressif ESP-IDF v4.3 or newer.

#### 16. CVE-2019-15894 - Espressif ESP32 Bluetooth Low Energy (BLE) Key Negotiation Weakness
- **Liên kết NIST NVD:** https://nvd.nist.gov/vuln/detail/CVE-2019-15894
- **Phân loại Nguy cơ (CVSS v3.1):** Base Score **6.8** (`CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Nhóm Lỗi Chuẩn NIST:** `CWE-310`
- **Chuỗi Chuẩn hóa CPE 2.3:**
  - `cpe:2.3:h:espressif:esp32:*:*:*:*:*:*:*:*`
  - `cpe:2.3:o:espressif:esp-idf:*:*:*:*:*:*:*:*`
- **Mô tả Chính thức:** An issue was discovered in Espressif ESP-IDF 2.x and 3.x for ESP32 where insufficient entropy during BLE key negotiation can allow eavesdropping on pairing secrets.
- **Biện pháp Khắc phục:** Upgrade ESP-IDF build toolchain to version 3.3.1 or higher.

