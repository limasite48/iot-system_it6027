"""
Real-time Network Traffic & Bandwidth Meter (net-sec)
Measures data traffic sent/received to IoT devices across the edge network interface
using high-frequency psutil performance counters.
"""

import time
import threading
import subprocess
import json
import platform
import psutil
from typing import Dict, Any, Optional

class TrafficMeter:
    def __init__(self, target_subnet_prefix: str = "192.168.137."):
        self.target_subnet_prefix = target_subnet_prefix
        self.interface_name: Optional[str] = None
        self._running = False
        self._lock = threading.Lock()
        
        # Cumulative and instantaneous metrics
        self.metrics = {
            "interface": "Unknown",
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
            "device_traffic": {}  # Per-device cumulative estimations
        }

        # Baseline counters for relative rate calculations
        self._prev_rx_bytes = 0
        self._prev_tx_bytes = 0
        self._prev_rx_packets = 0
        self._prev_tx_packets = 0
        self._prev_timestamp = time.time()

        self._detect_interface()

    def _detect_interface(self):
        """Identify which network adapter handles the IoT subnet dynamically."""
        detected = None
        try:
            from app.discovery.network_env import detect_active_subnets
            subnets = detect_active_subnets()
            # 1. Prioritize hotspot interface
            for s in subnets:
                if s.get("is_hotspot"):
                    detected = s["interface"]
                    break
            # 2. Fallback to active Wi-Fi or LAN
            if not detected and subnets:
                for s in subnets:
                    if not any(v in s["interface"].lower() for v in ["vethernet", "wsl", "docker", "loopback"]):
                        detected = s["interface"]
                        break
        except Exception:
            pass

        # Fallback to checking adapters with psutil
        if not detected:
            all_counters = psutil.net_io_counters(pernic=True)
            for name in all_counters.keys():
                if "Local Area Connection" in name or "Hotspot" in name.lower():
                    detected = name
                    break
            if not detected and "Wi-Fi" in all_counters:
                detected = "Wi-Fi"

        self.interface_name = detected or "Default Interface"
        with self._lock:
            self.metrics["interface"] = self.interface_name

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
        while self._running:
            try:
                time.sleep(1.0)
                now = time.time()
                dt = now - self._prev_timestamp
                if dt <= 0:
                    continue

                all_counters = psutil.net_io_counters(pernic=True)
                counters = all_counters.get(self.interface_name)

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
                        rx_rate_mb = rx_rate_kb / 1024.0
                        tx_rate_mb = tx_rate_kb / 1024.0

                        with self._lock:
                            self.metrics["is_active"] = True
                            self.metrics["total_rx_bytes"] = curr_rx
                            self.metrics["total_tx_bytes"] = curr_tx
                            self.metrics["total_rx_mb"] = round(curr_rx / (1024.0 * 1024.0), 2)
                            self.metrics["total_tx_mb"] = round(curr_tx / (1024.0 * 1024.0), 2)
                            self.metrics["rx_rate_kbps"] = round(rx_rate_kb, 1)
                            self.metrics["tx_rate_kbps"] = round(tx_rate_kb, 1)
                            self.metrics["rx_rate_mbps"] = round(rx_rate_mb, 2)
                            self.metrics["tx_rate_mbps"] = round(tx_rate_mb, 2)
                            self.metrics["packets_rx_sec"] = int(delta_rx_pkts / dt)
                            self.metrics["packets_tx_sec"] = int(delta_tx_pkts / dt)

                    self._prev_rx_bytes = curr_rx
                    self._prev_tx_bytes = curr_tx
                    self._prev_rx_packets = curr_rx_pkts
                    self._prev_tx_packets = curr_tx_pkts
                    self._prev_timestamp = now
            except Exception:
                pass

    def get_snapshot(self) -> Dict[str, Any]:
        """Return a copy of the current traffic metrics."""
        with self._lock:
            return dict(self.metrics)

# Global singleton
GLOBAL_TRAFFIC_METER = TrafficMeter()
GLOBAL_TRAFFIC_METER.start()
