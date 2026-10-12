#!/usr/bin/env python3
"""
IoT Security Audit Platform - Automated Performance & Operational Benchmark Harness
Course: IT6027 - Cybersecurity Policy and Governance
Fulfills Teacher Note 1 Item 2c: Empirical testing & performance measurement scenario.

Measures scan execution latency, discovery throughput, and resource utilization
as the network fleet scales across heterogeneous IoT devices.
"""

import sys
import os
import time
import json
import argparse
import asyncio
from datetime import datetime
from typing import List, Dict, Any

# Ensure path resolution
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
MOCK_OBJ_DIR = os.path.join(ROOT_DIR, "mock-object")

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if MOCK_OBJ_DIR not in sys.path:
    sys.path.insert(0, MOCK_OBJ_DIR)

import psutil
from app.scanner_engine import SecurityScannerEngine
from app.db.database import DatabaseManager
from fleet_manager import start_fleet, stop_fleet

def measure_memory_mb() -> float:
    """Measure current process RSS memory in MB."""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)

async def run_benchmark_cycle(scanner: SecurityScannerEngine, target_cidr: str) -> Dict[str, Any]:
    """Execute a single complete audit cycle and measure fine-grained stage latencies."""
    start_mem = measure_memory_mb()
    t0 = time.perf_counter()
    
    # Execute full 7-stage network audit pipeline
    cataloged = await scanner.execute_network_scan(target_cidr=target_cidr, timeout_discovery=1.5)
    
    total_time = time.perf_counter() - t0
    end_mem = measure_memory_mb()

    # Aggregate finding metrics
    total_cves = sum(len(d.get("cves", [])) for d in cataloged)
    def_creds = sum(1 for d in cataloged if d.get("default_credentials_found"))
    quarantined = sum(1 for d in cataloged if d.get("scoping_policy", {}).get("quarantine_required"))

    return {
        "devices_discovered": len(cataloged),
        "total_time_seconds": round(total_time, 3),
        "throughput_devices_per_sec": round(len(cataloged) / total_time if total_time > 0 else 0, 2),
        "memory_start_mb": round(start_mem, 2),
        "memory_end_mb": round(end_mem, 2),
        "memory_delta_mb": round(end_mem - start_mem, 2),
        "total_cves_matched": total_cves,
        "default_credentials_found": def_creds,
        "quarantined_devices": quarantined
    }

async def benchmark_fleet_scaling(device_counts: List[int], out_file: str = None) -> List[Dict[str, Any]]:
    """Benchmark the audit engine across scaling device fleet sizes."""
    print("=" * 76)
    print("   IoT SECURITY AUDIT PLATFORM - EMPIRICAL PERFORMANCE BENCHMARK")
    print("             Course: IT6027 - Teacher Note 1 Item 2c")
    print("=" * 76)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Platform: {sys.platform} | Python: {sys.version.split()[0]}")
    print(f"Scaling Target Counts: {device_counts}")
    print("-" * 76)

    # Use in-memory SQLite database for benchmark isolation
    test_db = DatabaseManager(db_path=":memory:")
    scanner = SecurityScannerEngine(db_manager=test_db)

    results = []

    for count in device_counts:
        print(f"\n[*] Provisioning testbed with {count} simulated IoT node(s)...")
        stop_fleet()
        time.sleep(0.5)

        start_fleet(count=count, use_loopback_ips=True)
        time.sleep(1.0)  # Allow mock servers to bind sockets

        try:
            print(f"[*] Executing benchmark audit for fleet size {count}...")
            metrics = await run_benchmark_cycle(scanner, target_cidr="127.0.0.0/24")
            metrics["fleet_size"] = count
            results.append(metrics)
            print(f"    -> Discovered: {metrics['devices_discovered']} nodes in {metrics['total_time_seconds']}s")
            print(f"    -> Throughput: {metrics['throughput_devices_per_sec']} devices/sec")
            print(f"    -> Memory RSS: {metrics['memory_end_mb']} MB (Delta: +{metrics['memory_delta_mb']} MB)")
            print(f"    -> Security Findings: {metrics['total_cves_matched']} CVEs, {metrics['default_credentials_found']} default creds, {metrics['quarantined_devices']} quarantined")
        finally:
            stop_fleet()
            time.sleep(0.5)

    print("\n" + "=" * 76)
    print("                     BENCHMARK SUMMARY TABLE")
    print("=" * 76)
    print("| Fleet Size | Devices Found | Audit Latency (s) | Throughput (dev/s) | Memory (MB) | Matched CVEs |")
    print("| :---: | :---: | :---: | :---: | :---: | :---: |")
    for r in results:
        print(f"| {r['fleet_size']:^10} | {r['devices_discovered']:^13} | {r['total_time_seconds']:^17} | {r['throughput_devices_per_sec']:^18} | {r['memory_end_mb']:^11} | {r['total_cves_matched']:^12} |")
    print("=" * 76)

    if out_file:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "results": results
            }, f, indent=2)
        print(f"[+] Benchmark results exported to: {out_file}")

    return results

def main():
    parser = argparse.ArgumentParser(description="IoT Insecure Device Detection Performance Benchmark")
    parser.add_argument(
        "--devices", "--max-devices", "--device", "--count",
        dest="devices",
        type=str,
        default="1,4",
        help="Device counts or max device count to benchmark (e.g. '1,4' or '4' or '1,4,8')"
    )
    parser.add_argument("--out", type=str, default=None, help="Optional output JSON file for report artifacts")
    args = parser.parse_args()

    raw_items = [x.strip() for x in args.devices.split(",") if x.strip().isdigit()]
    counts = [int(x) for x in raw_items]
    if not counts:
        counts = [1, 4]
    elif len(counts) == 1 and counts[0] > 1:
        counts = [1, counts[0]]

    asyncio.run(benchmark_fleet_scaling(counts, args.out))

if __name__ == "__main__":
    main()
