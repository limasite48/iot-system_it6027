#!/usr/bin/env python3
"""
IoT Security Platform Database Cleaner & Maintenance Utility
Course: IT6027 - Cyber Security Policy and Governance

Removes stale loopback nodes (127.0.0.X) and transient network gateway IPs
so the SOC Dashboard reflects only genuine mock containers and physical edge devices.
"""

import os
import sqlite3
import json

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "iot_security.db")

def clean_database(purge_all_loopback: bool = True, purge_gateways: bool = True, purge_mocks: bool = False):
    if not os.path.exists(DB_PATH):
        print(f"[*] No database found at {DB_PATH}. Nothing to clean.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM devices")
    total_before = cur.fetchone()[0]

    deleted_count = 0
    if purge_all_loopback:
        cur.execute("DELETE FROM devices WHERE ip LIKE '127.0.0.%'")
        deleted_count += cur.rowcount

    if purge_gateways:
        cur.execute("DELETE FROM devices WHERE ip IN ('172.28.10.1', '172.28.99.1', '192.168.137.1') OR (ip LIKE '%.1' AND ip != '127.0.0.1')")
        deleted_count += cur.rowcount

    if purge_mocks:
        cur.execute("DELETE FROM devices WHERE ip LIKE '172.28.10.%' OR ip LIKE '172.28.99.%'")
        deleted_count += cur.rowcount
        try:
            cur.execute("DELETE FROM triage_findings WHERE target_ip LIKE '172.28.%' OR target_ip LIKE '127.0.0.%'")
            cur.execute("DELETE FROM alerts WHERE device_ip LIKE '172.28.%' OR device_ip LIKE '127.0.0.%'")
        except Exception:
            pass

    conn.commit()

    cur.execute("SELECT ip, device_type, vendor, is_online FROM devices")
    remaining = cur.fetchall()
    conn.close()

    print("====================================================================")
    print(" IoT Security Database Cleanup Completed")
    if purge_mocks:
        print(" Mode: Real-Only Purge (Simulated mock devices removed)")
    print("====================================================================")
    print(f" [+] Total records before: {total_before}")
    print(f" [-] Stale ghost/mock records removed: {deleted_count}")
    print(f" [=] Clean active devices remaining: {len(remaining)}")
    print("--------------------------------------------------------------------")
    for r in remaining:
        status = "ONLINE" if r[3] else "OFFLINE"
        print(f"  * {r[0]:<16} | {r[1]:<28} | {r[2]:<30} | [{status}]")
    print("====================================================================\n")

if __name__ == "__main__":
    import sys
    is_real = any(arg in ["--real-only", "-r", "0", "--purge-mocks"] for arg in sys.argv[1:])
    clean_database(purge_mocks=is_real)
