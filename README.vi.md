# Hệ thống phát hiện thiết bị IoT không an toàn trong mạng

**Môn học:** IT6027 - Chính sách và Quản trị An toàn thông tin
**Phiên bản:** v0.2.2 · **Kiểm thử:** 123 test tự động (pass)

Tài liệu này hướng dẫn **chạy hệ thống trên macOS** (và tham chiếu nhanh cho Windows/Linux/Docker), kèm các **kịch bản demo** gồm cả kịch bản dùng **WiFi do điện thoại phát**.

---

## 1. Hệ thống làm được gì

| Nhóm | Chức năng | Mô tả ngắn |
| :-- | :-- | :-- |
| **Bắt buộc** | Fingerprint thiết bị IoT | Quét cổng → lấy banner (HTTP/RTSP/Telnet/MQTT), nghe mDNS/Zeroconf, dò UPnP/SSDP, tra OUI MAC → phân loại Camera, Smart TV, Smart Plug, AC, Thermostat, Gateway, Sensor, Điện thoại |
| **Bắt buộc** | Đối chiếu Firmware/CVE + mật khẩu mặc định | Chuẩn hoá CPE 2.3, so khớp CSDL CVE đa nguồn (CVSS v3.1); kiểm thử **không phá huỷ** mật khẩu mặc định theo danh sách khai báo (`default_passwords.txt`) qua HTTP Basic/Digest, RTSP, Telnet |
| **Bonus** | VLAN scoping, cảnh báo, dashboard | Phân nhóm thiết bị theo VLAN, đề xuất cách ly (quarantine), webhook cảnh báo, dashboard web theo loại thiết bị |

Toàn bộ chạy ở chế độ **hộp đen, không phá huỷ** và chỉ quét trong phạm vi mạng edge được cấp phép (loopback testbed, hotspot). LAN gia đình và Internet (WAN) luôn bị từ chối quét.

---

## 2. Chuẩn bị (macOS)

Yêu cầu: **Python 3.10+** (có sẵn `python3` trên Mac), hoặc Docker Desktop/Colima nếu chạy bằng Docker.

```bash
cd iot-system_it6027

# (khuyến nghị) tạo môi trường ảo
python3 -m venv .venv && source .venv/bin/activate

# cài phụ thuộc
pip install -r net-sec/requirements.txt
```

### Lưu ý riêng cho macOS (quan trọng)

Hệ thống mô phỏng (mock fleet) cho mỗi thiết bị ảo một IP loopback riêng: `127.0.0.2`, `127.0.0.3`, … Trên **Linux** cả dải `127.0.0.0/8` tự trỏ về loopback; **macOS chỉ mở `127.0.0.1`**, nên cần 2 điều:

1. **Alias loopback** cho `127.0.0.2+`. Chạy bằng `sudo` thì hệ thống **tự tạo** alias. Nếu chạy không `sudo` mà thiếu alias, chương trình sẽ in sẵn lệnh để bạn chạy **một lần** (alias tồn tại đến khi khởi động lại máy):
   ```bash
   sudo ifconfig lo0 alias 127.0.0.2 up && sudo ifconfig lo0 alias 127.0.0.3 up \
     && sudo ifconfig lo0 alias 127.0.0.4 up && sudo ifconfig lo0 alias 127.0.0.5 up
   ```
2. **Cổng < 1024** (vài profile dùng port 80/554 như Dahua, Hikvision) cần quyền root trên macOS.

> **Khuyến nghị trên Mac: chạy bằng `sudo`** để bật đủ 15 loại thiết bị (gồm các camera dính CVE dùng port 80/554) và tự tạo alias loopback:
> ```bash
> sudo python3 run.py
> ```
> Chạy **không** `sudo` vẫn hoạt động, nhưng các node dùng port 80/554 sẽ bị bỏ qua (vẫn còn D-Link default-creds, Smart TV, Samsung… để demo).

---

## 3. Các cách chạy

### 3.1. Chế độ All-in-One + Dashboard (mặc định, khuyến nghị để demo)

Tự khởi động 4 thiết bị IoT ảo trên loopback, mở audit engine và dashboard SOC, tự quét lúc khởi động:

```bash
sudo python3 run.py
```

Mở trình duyệt: **http://localhost:8000**

Tuỳ chọn:

| Lệnh | Ý nghĩa |
| :-- | :-- |
| `sudo python3 run.py` | Dashboard đầy đủ, 4 node ảo (mặc định) |
| `sudo python3 run.py --device 8` | Tăng số thiết bị ảo (chấp nhận `--device`/`--devices`/`--cameras`) |
| `python3 run.py --port 8090` | Đổi cổng web dashboard |
| `python3 run.py --no-fleet` | Tắt mock fleet — chỉ quét thiết bị vật lý thật trên mạng |
| `python3 run.py --target 172.20.10.0/28` | Giới hạn quét vào một dải CIDR/IP cụ thể |

Dừng: nhấn **Ctrl+C** (tự tắt toàn bộ thiết bị ảo và web server).

### 3.2. Chế độ quét một lần ra terminal (CLI)

Không cần mở dashboard, in báo cáo ra màn hình:

```bash
sudo python3 run.py --scan --target 127.0.0.0/24      # quét testbed ảo
python3 run.py --scan --no-fleet --target 172.20.10.0/28   # quét mạng hotspot thật
```

### 3.3. Chế độ Docker (đa nền tảng, không cần sửa macOS)

Dựng đồng thời Auditor + dashboard, MQTT broker và dàn camera mock trên các subnet Docker ảo (VLAN 10 / VLAN 99). **Không đụng tới loopback của máy Mac** nên không cần alias/sudo:

```bash
docker compose up --build -d      # dựng nền
# mở http://localhost:8000
docker compose logs -f net-sec    # xem log
docker compose down               # dừng và dọn
```

> Xem thêm chi tiết kiến trúc container trong `DOCKER_INSTRUCTIONS.md`.

### 3.4. Chạy riêng từng phần (nâng cao)

```bash
# chỉ dựng dàn thiết bị ảo
sudo python3 mock-object/fleet_manager.py start-fleet --devices 6
python3 mock-object/fleet_manager.py list      # xem trạng thái
python3 mock-object/fleet_manager.py stop      # dừng tất cả

# chỉ chạy auditor/web (trỏ sys.path vào net-sec)
cd net-sec && python3 run_scanner.py --web --port 8000
```

---

## 4. Các kịch bản demo

### Kịch bản A — Testbed ảo trên chính máy Mac (nhanh nhất, không cần phần cứng)

1. `sudo python3 run.py`
2. Mở **http://localhost:8000**. Bấm **Scan** (hoặc đợi quét tự động lúc khởi động).
3. Quan sát dashboard:
   - **D-Link DCS-932L** (`127.0.0.2`): `Risk=CRITICAL`, phát hiện **mật khẩu mặc định `admin:admin`** + **CVE-2020-25078 (CVSS 9.8)**, đề xuất **cách ly VLAN 99**.
   - **Sony BRAVIA / ProSafe Cam / Nest…**: baseline an toàn, `Risk=LOW`.
   - Các camera dùng port 80/554 (Dahua backdoor, Hikvision CVE-2021-36260) chỉ xuất hiện khi chạy bằng `sudo`.

Kết quả kỳ vọng (CLI tương đương): "Total Nodes", "Default Passwords Found", "Quarantine Isolation Actions" > 0.

### Kịch bản B — WiFi do điện thoại phát (demo mạng vật lý thật) ⭐

Mô phỏng đúng đề bài: điện thoại làm điểm phát sóng, các thiết bị thật nối vào, máy Mac chạy hệ thống quét.

**Bước 1 — Điện thoại phát WiFi (điểm truy cập):**
- **iPhone:** Cài đặt → Điểm truy cập cá nhân → *Cho phép người khác tham gia*. Dải mạng iPhone cấp là **`172.20.10.0/28`**.
- **Android:** Cài đặt → Điểm phát sóng & chia sẻ kết nối → *Điểm phát sóng WiFi*. Dải thường là **`192.168.43.0/24`**.

**Bước 2 — Máy Mac (máy chạy hệ thống) nối vào WiFi vừa phát.**
Kiểm tra IP Mac nhận được:
```bash
ipconfig getifaddr en0     # ví dụ 172.20.10.3 (iPhone) hoặc 192.168.43.x (Android)
```

**Bước 3 — "Thiết bị A" nối vào cùng WiFi đó.**
Dùng một thiết bị bất kỳ làm "thiết bị IoT": một điện thoại khác, laptop, IP camera, hoặc board ESP32. Nếu muốn có cổng/dịch vụ để hệ thống nhìn thấy rõ, cài **"IP Webcam"** (Android) hoặc bật một web server đơn giản trên thiết bị A — khi đó nó sẽ lộ banner HTTP/stream để fingerprint.

**Bước 4 — Chạy hệ thống trên Mac, chỉ quét dải hotspot (không cần fleet ảo):**
```bash
# iPhone hotspot
python3 run.py --no-fleet --target 172.20.10.0/28
# hoặc Android hotspot
python3 run.py --no-fleet --target 192.168.43.0/24
```
Hoặc mở dashboard rồi nhập dải này vào ô target:
```bash
python3 run.py --no-fleet
# mở http://localhost:8000, nhập 172.20.10.0/28 và bấm Scan
```

**Bước 5 — Xem dashboard:** thiết bị A (và chính điện thoại) hiện lên dưới VLAN *"iPhone/Android Hotspot WLAN"*, kèm loại thiết bị suy ra từ MAC/banner/mDNS, cổng mở, và kết quả kiểm CVE/mật khẩu mặc định nếu có dịch vụ.

> Hệ thống đã được cấu hình nhận dải hotspot điện thoại (`172.20.10.0/28`, `192.168.43.0/24`) là mạng edge hợp lệ. Dải LAN gia đình (vd `192.168.1.0/24`) và Internet **sẽ bị từ chối quét** theo chính sách scope — đây là hành vi đúng.

**Mẹo trình chiếu:** vì web bind `0.0.0.0`, bạn có thể mở dashboard từ một thiết bị khác trong cùng hotspot qua `http://<IP-của-Mac>:8000` (vd `http://172.20.10.3:8000`).

### Kịch bản C — Trình diễn bằng Docker (máy chấm chỉ cần Docker)

```bash
docker compose up --build -d
# mở http://localhost:8000, bấm Scan (target ALL)
```
Dashboard hiển thị dàn camera mock trên VLAN 10/99 với đầy đủ CVE và mật khẩu mặc định — không phụ thuộc cấu hình mạng của máy host.

---

## 5. Xử lý sự cố (macOS)

| Hiện tượng | Nguyên nhân / cách xử lý |
| :-- | :-- |
| Dashboard trống, "Identified 0 target IP(s)" ở chế độ testbed | Thiếu alias loopback. Chạy lại bằng `sudo python3 run.py`, hoặc chạy lệnh `ifconfig lo0 alias …` ở Mục 2. |
| Thiếu vài node (vd Dahua, Hikvision, Daikin) | Các profile đó dùng port 80/554 cần root → chạy `sudo python3 run.py`. |
| "Scope Violation" khi quét hotspot | Đảm bảo target đúng dải hotspot (`172.20.10.0/28` iPhone / `192.168.43.0/24` Android). LAN nhà bị chặn là đúng thiết kế. |
| Thiết bị A không hiện | Thiết bị A phải **cùng** WiFi hotspot; nên có ít nhất một cổng TCP mở (HTTP/stream) để fingerprint. Thử lại sau khi mở app IP Webcam / web server trên thiết bị A. |
| Cổng 8000 bận | Đổi cổng: `python3 run.py --port 8090`. |
| Còn tiến trình mock sót | `python3 mock-object/fleet_manager.py stop` hoặc `pkill -f camera_server.py`. |

---

## 6. Kiểm thử

```bash
python3 -m pytest net-sec/tests mock-object/tests -q
# kỳ vọng: 123 passed
```
