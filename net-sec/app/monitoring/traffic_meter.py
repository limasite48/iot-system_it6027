"""
Real-time Network Traffic & Bandwidth Meter (net-sec)
Measures data traffic sent/received across the edge network interface
and provides isolated, per-device bandwidth attribution using psutil performance counters
and socket connection sampling. Eliminates cross-device traffic leakage between
hotspot clients and virtual mock devices.
"""

import time
import threading
import ipaddress
import platform
import psutil
from typing import Dict, Any, Optional, Set, List

class TrafficMeter:
    def __init__(self, target_subnet_prefix: Optional[str] = None):
        self.target_subnet_prefix = target_subnet_prefix
        self.interface_name: Optional[str] = None
        self.loopback_name: Optional[str] = None
        self._running = False
        self._lock = threading.Lock()
        
        # Cumulative and instantaneous metrics
        self.metrics = {
            "interface": "Unknown",
            "loopback_interface": "Unknown",
            "is_active": False,
            "total_rx_bytes": 0,
            "total_tx_bytes": 0,
            "total_rx_mb": 0.0,
            "total_tx_mb": 0.0,
            "rx_rate_kbps": 0.0,
            "tx_rate_kbps": 0.0,
            "rx_rate_mbps": 0.0,
            "tx_rate_mbps": 0.0,
            "packets_rx_sec": 0,
            "packets_tx_sec": 0,
            "device_traffic": {}  # Per-device cumulative & instantaneous metrics
        }

        # Baseline counters for relative rate calculations (Hotspot)
        self._prev_rx_bytes = 0
        self._prev_tx_bytes = 0
        self._prev_rx_packets = 0
        self._prev_tx_packets = 0

        # Baseline counters for relative rate calculations (Loopback)
        self._prev_loopback_rx = 0
        self._prev_loopback_tx = 0

        # Per-device cumulative tracking
        self._device_stats: Dict[str, Dict[str, Any]] = {}
        self._prev_timestamp = time.time()
        self._loop_count = 0

        self._detect_interface()

    def _detect_interface(self):
        """Identify which network adapter handles the IoT subnet dynamically, and find loopback."""
        detected = None
        detected_prefix = None
        try:
            from app.discovery.network_env import detect_active_subnets
            subnets = detect_active_subnets()
            # 1. Prioritize hotspot interface
            for s in subnets:
                if s.get("is_hotspot"):
                    detected = s["interface"]
                    detected_prefix = s.get("network_address")
                    break
            # 2. Fallback to active Wi-Fi or LAN
            if not detected and subnets:
                for s in subnets:
                    if not any(v in s["interface"].lower() for v in ["vethernet", "wsl", "docker", "loopback"]):
                        detected = s["interface"]
                        detected_prefix = s.get("network_address")
                        break
        except Exception:
            pass

        all_counters = psutil.net_io_counters(pernic=True)

        # Fallback to checking adapters with psutil
        if not detected:
            for name in all_counters.keys():
                if "Local Area Connection" in name or "Hotspot" in name.lower():
                    detected = name
                    break
            if not detected and "Wi-Fi" in all_counters:
                detected = "Wi-Fi"

        # Detect loopback interface name
        loopback_iface = None
        for name in all_counters.keys():
            if "loopback" in name.lower() or name == "lo":
                loopback_iface = name
                break

        if not self.target_subnet_prefix and detected_prefix:
            parts = detected_prefix.split(".")
            if len(parts) >= 3:
                self.target_subnet_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."
        if not self.target_subnet_prefix:
            self.target_subnet_prefix = "192.168.137."

        self.interface_name = detected or "Default Interface"
        self.loopback_name = loopback_iface

        with self._lock:
            self.metrics["interface"] = self.interface_name
            self.metrics["loopback_interface"] = self.loopback_name or "None"

    def register_device(self, ip: str):
        """Pre-register an IP so it appears in device_traffic with zero baseline."""
        with self._lock:
            if ip not in self._device_stats:
                self._device_stats[ip] = {
                    "ip": ip,
                    "rx_rate_kbps": 0.0,
                    "tx_rate_kbps": 0.0,
                    "rx_rate_mbps": 0.0,
                    "tx_rate_mbps": 0.0,
                    "total_rx_mb": 0.0,
                    "total_tx_mb": 0.0,
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                    "is_streaming": False,
                    "active_conns": 0
                }
                self.metrics["device_traffic"][ip] = dict(self._device_stats[ip])

    def start(self):
        """Start the background sampling thread."""
        if self._running:
            return
        self._running = True
        self._detect_interface()
        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()

    def stop(self):
        self._running = False

    def _monitor_loop(self):
        CAMERA_PORTS = {80, 8080, 8081, 8443, 554, 4747}

        while self._running:
            try:
                time.sleep(1.0)
                now = time.time()
                dt = now - self._prev_timestamp
                if dt <= 0:
                    continue

                self._loop_count += 1
                # Periodically re-detect interface in case Hotspot was activated after startup
                if self._loop_count % 15 == 0 or self.interface_name == "Default Interface":
                    self._detect_interface()

                all_counters = psutil.net_io_counters(pernic=True)
                counters = all_counters.get(self.interface_name)
                loopback_counters = all_counters.get(self.loopback_name) if self.loopback_name else None

                delta_rx = 0
                delta_tx = 0
                delta_rx_pkts = 0
                delta_tx_pkts = 0

                if counters:
                    curr_rx = counters.bytes_recv
                    curr_tx = counters.bytes_sent
                    curr_rx_pkts = counters.packets_recv
                    curr_tx_pkts = counters.packets_sent

                    if self._prev_rx_bytes > 0:
                        delta_rx = max(0, curr_rx - self._prev_rx_bytes)
                        delta_tx = max(0, curr_tx - self._prev_tx_bytes)
                        delta_rx_pkts = max(0, curr_rx_pkts - self._prev_rx_packets)
                        delta_tx_pkts = max(0, curr_tx_pkts - self._prev_tx_packets)

                        rx_rate_kb = (delta_rx / 1024.0) / dt
                        tx_rate_kb = (delta_tx / 1024.0) / dt

                        with self._lock:
                            self.metrics["is_active"] = True
                            self.metrics["total_rx_bytes"] = curr_rx
                            self.metrics["total_tx_bytes"] = curr_tx
                            self.metrics["total_rx_mb"] = round(curr_rx / (1024.0 * 1024.0), 2)
                            self.metrics["total_tx_mb"] = round(curr_tx / (1024.0 * 1024.0), 2)
                            self.metrics["rx_rate_kbps"] = round(rx_rate_kb, 1)
                            self.metrics["tx_rate_kbps"] = round(tx_rate_kb, 1)
                            self.metrics["rx_rate_mbps"] = round(rx_rate_kb / 1024.0, 2)
                            self.metrics["tx_rate_mbps"] = round(tx_rate_kb / 1024.0, 2)
                            self.metrics["packets_rx_sec"] = int(delta_rx_pkts / dt)
                            self.metrics["packets_tx_sec"] = int(delta_tx_pkts / dt)

                    self._prev_rx_bytes = curr_rx
                    self._prev_tx_bytes = curr_tx
                    self._prev_rx_packets = curr_rx_pkts
                    self._prev_tx_packets = curr_tx_pkts

                # Loopback counters
                loopback_delta_rx = 0
                loopback_delta_tx = 0
                if loopback_counters:
                    curr_lb_rx = loopback_counters.bytes_recv
                    curr_lb_tx = loopback_counters.bytes_sent
                    if self._prev_loopback_rx > 0:
                        loopback_delta_rx = max(0, curr_lb_rx - self._prev_loopback_rx)
                        loopback_delta_tx = max(0, curr_lb_tx - self._prev_loopback_tx)
                    self._prev_loopback_rx = curr_lb_rx
                    self._prev_loopback_tx = curr_lb_tx

                self._prev_timestamp = now

                # -----------------------------------------------------------------
                # Isolated Per-Device Attribution
                # -----------------------------------------------------------------
                hotspot_active_ips: Dict[str, int] = {}
                loopback_active_ips: Dict[str, int] = {}
                streaming_ips: Set[str] = set()

                try:
                    conns = psutil.net_connections(kind="inet")
                    for c in conns:
                        r_ip = c.raddr.ip if c.raddr else None
                        r_port = c.raddr.port if c.raddr else None
                        l_ip = c.laddr.ip if c.laddr else None
                        l_port = c.laddr.port if c.laddr else None

                        if r_ip and not r_ip.startswith("127.") and not r_ip.startswith("0."):
                            target_ip = r_ip
                            if r_port in CAMERA_PORTS or l_port in CAMERA_PORTS:
                                streaming_ips.add(target_ip)
                            hotspot_active_ips[target_ip] = hotspot_active_ips.get(target_ip, 0) + 1
                        elif r_ip and r_ip.startswith("127.") and r_ip != "127.0.0.1":
                            target_ip = r_ip
                            if r_port in CAMERA_PORTS or l_port in CAMERA_PORTS:
                                streaming_ips.add(target_ip)
                            loopback_active_ips[target_ip] = loopback_active_ips.get(target_ip, 0) + 1
                        elif l_ip and l_ip.startswith("127.") and l_ip != "127.0.0.1" and c.status == "ESTABLISHED":
                            loopback_active_ips[l_ip] = loopback_active_ips.get(l_ip, 0) + 1
                except Exception:
                    pass

                prefix = self.target_subnet_prefix or "192.168.137."

                with self._lock:
                    known_ips = set(self._device_stats.keys())
                    all_tracked_ips = known_ips.union(hotspot_active_ips.keys()).union(loopback_active_ips.keys())

                    # Attribute Hotspot Delta Rx/Tx strictly to Hotspot Devices
                    hotspot_candidates = [
                        ip for ip in all_tracked_ips 
                        if (ip.startswith(prefix) or (not ip.startswith("127.") and not ip.startswith("172.28.")))
                        and ip not in ["127.0.0.1", "localhost"]
                    ]
                    
                    if hotspot_candidates and (delta_rx > 0 or delta_tx > 0):
                        active_streaming_candidates = [ip for ip in hotspot_candidates if ip in streaming_ips or ip in hotspot_active_ips]
                        recipients = active_streaming_candidates if active_streaming_candidates else hotspot_candidates
                        share_rx = delta_rx / float(len(recipients))
                        share_tx = delta_tx / float(len(recipients))

                        for ip in recipients:
                            dev = self._device_stats.setdefault(ip, {
                                "ip": ip, "rx_bytes": 0, "tx_bytes": 0,
                                "rx_rate_kbps": 0.0, "tx_rate_kbps": 0.0,
                                "rx_rate_mbps": 0.0, "tx_rate_mbps": 0.0,
                                "total_rx_mb": 0.0, "total_tx_mb": 0.0,
                                "is_streaming": False, "active_conns": 0
                            })
                            dev["rx_bytes"] += int(share_rx)
                            dev["tx_bytes"] += int(share_tx)
                            dev_rx_rate_kb = (share_rx / 1024.0) / dt
                            dev_tx_rate_kb = (share_tx / 1024.0) / dt
                            dev["rx_rate_kbps"] = round(dev_rx_rate_kb, 1)
                            dev["tx_rate_kbps"] = round(dev_tx_rate_kb, 1)
                            dev["rx_rate_mbps"] = round(dev_rx_rate_kb / 1024.0, 2)
                            dev["tx_rate_mbps"] = round(dev_tx_rate_kb / 1024.0, 2)
                            dev["total_rx_mb"] = round(dev["rx_bytes"] / (1024.0 * 1024.0), 2)
                            dev["total_tx_mb"] = round(dev["tx_bytes"] / (1024.0 * 1024.0), 2)
                            dev["is_streaming"] = (dev_rx_rate_kb > 5.0) or (ip in streaming_ips)
                            dev["active_conns"] = hotspot_active_ips.get(ip, 0)

                    # Attribute Loopback Delta Rx/Tx (ONLY to 127.0.0.x with active connections)
                    if loopback_active_ips and (loopback_delta_rx > 0 or loopback_delta_tx > 0):
                        lb_recipients = list(loopback_active_ips.keys())
                        share_lb_rx = loopback_delta_rx / float(len(lb_recipients))
                        share_lb_tx = loopback_delta_tx / float(len(lb_recipients))
                        for ip in lb_recipients:
                            dev = self._device_stats.setdefault(ip, {
                                "ip": ip, "rx_bytes": 0, "tx_bytes": 0,
                                "rx_rate_kbps": 0.0, "tx_rate_kbps": 0.0,
                                "rx_rate_mbps": 0.0, "tx_rate_mbps": 0.0,
                                "total_rx_mb": 0.0, "total_tx_mb": 0.0,
                                "is_streaming": False, "active_conns": 0
                            })
                            dev["rx_bytes"] += int(share_lb_rx)
                            dev["tx_bytes"] += int(share_lb_tx)
                            dev_rx_rate_kb = (share_lb_rx / 1024.0) / dt
                            dev_tx_rate_kb = (share_lb_tx / 1024.0) / dt
                            dev["rx_rate_kbps"] = round(dev_rx_rate_kb, 1)
                            dev["tx_rate_kbps"] = round(dev_tx_rate_kb, 1)
                            dev["rx_rate_mbps"] = round(dev_rx_rate_kb / 1024.0, 2)
                            dev["tx_rate_mbps"] = round(dev_tx_rate_kb / 1024.0, 2)
                            dev["total_rx_mb"] = round(dev["rx_bytes"] / (1024.0 * 1024.0), 2)
                            dev["total_tx_mb"] = round(dev["tx_bytes"] / (1024.0 * 1024.0), 2)
                            dev["is_streaming"] = (dev_rx_rate_kb > 5.0) or (ip in streaming_ips)
                            dev["active_conns"] = loopback_active_ips.get(ip, 0)

                    # For devices with no delta this second, decay rate to 0.0 KB/s
                    for ip, dev in self._device_stats.items():
                        if ip.startswith("127."):
                            if ip not in loopback_active_ips or loopback_delta_rx == 0:
                                dev["rx_rate_kbps"] = 0.0
                                dev["tx_rate_kbps"] = 0.0
                                dev["rx_rate_mbps"] = 0.0
                                dev["tx_rate_mbps"] = 0.0
                                dev["is_streaming"] = False
                                dev["active_conns"] = loopback_active_ips.get(ip, 0)
                        else:
                            if ip not in hotspot_active_ips and delta_rx == 0:
                                dev["rx_rate_kbps"] = 0.0
                                dev["tx_rate_kbps"] = 0.0
                                dev["rx_rate_mbps"] = 0.0
                                dev["tx_rate_mbps"] = 0.0
                                dev["is_streaming"] = False
                                dev["active_conns"] = hotspot_active_ips.get(ip, 0)

                    self.metrics["device_traffic"] = {k: dict(v) for k, v in self._device_stats.items()}

            except Exception:
                pass

    def get_snapshot(self) -> Dict[str, Any]:
        """Return a copy of the current traffic metrics."""
        with self._lock:
            snap = dict(self.metrics)
            snap["device_traffic"] = {k: dict(v) for k, v in self._device_stats.items()}
            return snap

# Global singleton
GLOBAL_TRAFFIC_METER = TrafficMeter()
GLOBAL_TRAFFIC_METER.start()
