"""
SQLite Persistence Engine (net-sec)
Course: IT6027 - Cybersecurity Policy and Governance
Provides relational data storage, durability across restarts, and database schema compliance.
Zero external dependencies, utilizes Python's built-in sqlite3.
"""

import os
import json
import sqlite3
import threading
import contextlib
from datetime import datetime
from typing import Dict, Any, List, Optional

DEFAULT_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "iot_security.db"))
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

class DatabaseManager:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self._lock = threading.RLock()
        self._initialized = False
        self.init_db()

    @contextlib.contextmanager
    def _get_connection(self):
        """Create and configure a thread-safe connection with dictionary cursor, closing on exit."""
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
        except Exception:
            pass
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self):
        """Ensure database schema is created and tables exist."""
        with self._lock:
            if self.db_path != ":memory:":
                db_dir = os.path.dirname(self.db_path)
                if db_dir and not os.path.exists(db_dir):
                    os.makedirs(db_dir, exist_ok=True)

            if os.path.exists(SCHEMA_PATH):
                with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
                    schema_sql = f.read()
            else:
                schema_sql = ""

            with self._get_connection() as conn:
                if schema_sql:
                    conn.executescript(schema_sql)
                conn.commit()
            self._initialized = True

    def save_scan(self, scan: Dict[str, Any]):
        """Insert or update a scan orchestration session record."""
        with self._lock:
            scan_id = scan.get("scan_id", "")
            if not scan_id:
                return
            target_cidr = scan.get("target_cidr", "ALL")
            start_time = scan.get("start_time", datetime.now().isoformat())
            end_time = scan.get("end_time")
            status = scan.get("status", "IN_PROGRESS")
            stage = scan.get("stage", "IDLE")
            devices_count = scan.get("devices_discovered", 0)

            sql = """
            INSERT INTO scans (scan_id, target_cidr, start_time, end_time, status, stage, devices_discovered)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                end_time = excluded.end_time,
                status = excluded.status,
                stage = excluded.stage,
                devices_discovered = excluded.devices_discovered;
            """
            with self._get_connection() as conn:
                conn.execute(sql, (scan_id, target_cidr, start_time, end_time, status, stage, devices_count))
                conn.commit()

    def save_device(self, device: Dict[str, Any], scan_id: Optional[str] = None):
        """Upsert a discovered device and its open ports into the relational database."""
        with self._lock:
            ip = device.get("ip")
            if not ip:
                return

            mac = device.get("mac", "Unknown")
            vendor = device.get("vendor", "Unknown")
            model = device.get("model", "Unspecified")
            device_type = device.get("device_type", "Generic IoT Device")
            vlan_info = device.get("vlan", {})
            vlan_id = vlan_info.get("vlan_id") if isinstance(vlan_info, dict) else None
            vlan_name = vlan_info.get("name") if isinstance(vlan_info, dict) else str(vlan_info)
            risk_level = device.get("risk_level", "LOW")
            def_creds = 1 if device.get("default_credentials_found") else 0
            open_acc = 1 if device.get("is_open_access") else 0
            is_online = 1 if device.get("is_online", True) else 0
            last_audited = device.get("last_audited", datetime.now().isoformat())

            # Serialize raw payload for faithful recovery
            raw_json = json.dumps(device)

            upsert_dev_sql = """
            INSERT INTO devices (ip, mac, vendor, model, device_type, vlan_id, vlan_name,
                                risk_level, default_credentials_found, is_open_access, is_online,
                                raw_json, last_audited)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                mac = excluded.mac,
                vendor = excluded.vendor,
                model = excluded.model,
                device_type = excluded.device_type,
                vlan_id = excluded.vlan_id,
                vlan_name = excluded.vlan_name,
                risk_level = excluded.risk_level,
                default_credentials_found = excluded.default_credentials_found,
                is_open_access = excluded.is_open_access,
                is_online = excluded.is_online,
                raw_json = excluded.raw_json,
                last_audited = excluded.last_audited;
            """

            with self._get_connection() as conn:
                conn.execute(upsert_dev_sql, (
                    ip, mac, vendor, model, device_type, vlan_id, vlan_name,
                    risk_level, def_creds, open_acc, is_online, raw_json, last_audited
                ))

                # Save open ports
                open_ports = device.get("open_ports", [])
                banners = device.get("banners", {})
                for port in open_ports:
                    banner_str = ""
                    if str(port) in banners:
                        banner_str = str(banners[str(port)])
                    elif port in banners:
                        banner_str = str(banners[port])
                    conn.execute("""
                    INSERT OR REPLACE INTO device_ports (ip, port, protocol, service, banner)
                    VALUES (?, ?, 'tcp', ?, ?);
                    """, (ip, int(port), device_type, banner_str))

                # Save correlated CVE findings (deduplicated per scan and host)
                cves = device.get("cves", [])
                if scan_id:
                    conn.execute("DELETE FROM cve_findings WHERE ip = ? AND scan_id = ?;", (ip, scan_id))
                else:
                    conn.execute("DELETE FROM cve_findings WHERE ip = ? AND scan_id IS NULL;", (ip,))
                for cve in cves:
                    conn.execute("""
                    INSERT OR REPLACE INTO cve_findings (scan_id, ip, cve_id, title, severity, cvss_score,
                                              cpe, vex_status, exploitability, ssvc_action, description, remediation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        scan_id, ip, cve.get("cve_id", "UNKNOWN"), cve.get("title", ""),
                        cve.get("severity", "MEDIUM"), float(cve.get("cvss_score", 0.0)),
                        cve.get("cpe", ""), cve.get("vex_status", ""), cve.get("exploitability", ""),
                        cve.get("ssvc_action", ""), cve.get("description", ""), cve.get("remediation", "")
                    ))

                conn.commit()

    def save_triage_finding(self, finding: Dict[str, Any]):
        """Insert or update a finding in the auditor triage ledger."""
        with self._lock:
            finding_id = finding.get("finding_id")
            if not finding_id:
                return

            sql = """
            INSERT INTO triage_records (finding_id, target_ip, finding_type, title, severity,
                                       port, cve_id, rule_id, status, auditor_notes, reviewed_by,
                                       reviewed_at, created_at, details, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
                status = excluded.status,
                auditor_notes = excluded.auditor_notes,
                reviewed_by = excluded.reviewed_by,
                reviewed_at = excluded.reviewed_at,
                details = excluded.details,
                remediation = excluded.remediation;
            """
            with self._get_connection() as conn:
                conn.execute(sql, (
                    finding_id, finding.get("target_ip", ""), finding.get("finding_type", "GENERAL"),
                    finding.get("title", ""), finding.get("severity", "MEDIUM"), finding.get("port"),
                    finding.get("cve_id"), finding.get("rule_id"), finding.get("status", "PENDING"),
                    finding.get("auditor_notes", ""), finding.get("reviewed_by", ""),
                    finding.get("reviewed_at"), finding.get("created_at", datetime.now().isoformat()),
                    finding.get("details", ""), finding.get("remediation", "")
                ))
                conn.commit()

    def save_alert(self, alert: Dict[str, Any]):
        """Record an alert notification."""
        with self._lock:
            sql = """
            INSERT INTO alerts (timestamp, severity, device_ip, device_type, title, details)
            VALUES (?, ?, ?, ?, ?, ?);
            """
            with self._get_connection() as conn:
                conn.execute(sql, (
                    alert.get("timestamp", datetime.now().isoformat()),
                    alert.get("severity", "INFO"),
                    alert.get("device_ip", ""),
                    alert.get("device_type", ""),
                    alert.get("title", ""),
                    alert.get("details", "")
                ))
                conn.commit()

    def load_all_devices(self) -> Dict[str, Dict[str, Any]]:
        """Restore all device records from SQLite into memory dictionary."""
        with self._lock:
            devices = {}
            with self._get_connection() as conn:
                rows = conn.execute("SELECT ip, raw_json FROM devices ORDER BY last_audited DESC").fetchall()
                for r in rows:
                    if r["raw_json"]:
                        try:
                            devices[r["ip"]] = json.loads(r["raw_json"])
                        except Exception:
                            pass
            return devices

    def load_all_triage_findings(self) -> List[Dict[str, Any]]:
        """Restore all auditor triage records from SQLite."""
        with self._lock:
            findings = []
            with self._get_connection() as conn:
                rows = conn.execute("SELECT * FROM triage_records ORDER BY created_at DESC").fetchall()
                for r in rows:
                    findings.append(dict(r))
            return findings

    def load_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent scan execution history."""
        with self._lock:
            scans = []
            with self._get_connection() as conn:
                rows = conn.execute("SELECT * FROM scans ORDER BY start_time DESC LIMIT ?", (limit,)).fetchall()
                for r in rows:
                    scans.append(dict(r))
            return scans

    def load_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent security alerts."""
        with self._lock:
            alerts = []
            with self._get_connection() as conn:
                rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
                for r in rows:
                    alerts.append(dict(r))
            return alerts

    def get_db_stats(self) -> Dict[str, Any]:
        """Return diagnostic metrics including row counts and file size."""
        with self._lock:
            stats = {
                "db_path": self.db_path,
                "file_size_bytes": 0,
                "scans_count": 0,
                "devices_count": 0,
                "ports_count": 0,
                "cve_findings_count": 0,
                "triage_records_count": 0,
                "alerts_count": 0
            }
            if self.db_path != ":memory:" and os.path.exists(self.db_path):
                stats["file_size_bytes"] = os.path.getsize(self.db_path)

            with self._get_connection() as conn:
                stats["scans_count"] = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                stats["devices_count"] = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
                stats["ports_count"] = conn.execute("SELECT COUNT(*) FROM device_ports").fetchone()[0]
                stats["cve_findings_count"] = conn.execute("SELECT COUNT(*) FROM cve_findings").fetchone()[0]
                stats["triage_records_count"] = conn.execute("SELECT COUNT(*) FROM triage_records").fetchone()[0]
                stats["alerts_count"] = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            return stats

# Global singleton
GLOBAL_DB_MANAGER = DatabaseManager()
