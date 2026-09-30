"""
Scalable Multi-Feed CVE Manager & Synchronizer (net-sec)
Manages modular vulnerability feeds, dynamic hot-reloading, custom IoT bundles,
and on-demand NIST NVD 2.0 API synchronization for network scale-up scenarios.
"""

import os
import json
import asyncio
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional

FEEDS_DIR = os.path.join(os.path.dirname(__file__), "feeds")
LEGACY_DB_PATH = os.path.join(os.path.dirname(__file__), "cve_database.json")

class CveManager:
    """Central management and synchronization service for IoT vulnerability feeds."""

    def __init__(self, feeds_dir: str = FEEDS_DIR, fallback_path: str = LEGACY_DB_PATH):
        self.feeds_dir = feeds_dir
        self.fallback_path = fallback_path
        self._lock = threading.RLock()
        self._cves_by_id: Dict[str, Dict[str, Any]] = {}
        self._feed_metadata: Dict[str, Dict[str, Any]] = {}
        self.last_sync_time: Optional[str] = None
        self.reload_feeds()

    def reload_feeds(self) -> int:
        """Scan feeds directory and legacy database, reloading all entries atomically."""
        with self._lock:
            temp_cves: Dict[str, Dict[str, Any]] = {}
            temp_feeds: Dict[str, Dict[str, Any]] = {}

            # 1. Load modular feeds directory if present
            if os.path.isdir(self.feeds_dir):
                for filename in sorted(os.listdir(self.feeds_dir)):
                    if filename.endswith(".json"):
                        feed_path = os.path.join(self.feeds_dir, filename)
                        try:
                            with open(feed_path, "r", encoding="utf-8") as f:
                                entries = json.load(f)
                            if isinstance(entries, list):
                                count = 0
                                for entry in entries:
                                    cve_id = entry.get("cve_id")
                                    if cve_id:
                                        entry["_feed_source"] = filename
                                        temp_cves[cve_id] = entry
                                        count += 1
                                temp_feeds[filename] = {
                                    "entries_count": count,
                                    "path": feed_path,
                                    "loaded_at": datetime.now().isoformat()
                                }
                        except Exception as e:
                            print(f"[!] Warning reading feed {filename}: {e}")

            # 2. Fallback to legacy cve_database.json if no feeds were loaded
            if not temp_cves and os.path.exists(self.fallback_path):
                try:
                    with open(self.fallback_path, "r", encoding="utf-8") as f:
                        entries = json.load(f)
                    if isinstance(entries, list):
                        count = 0
                        for entry in entries:
                            cve_id = entry.get("cve_id")
                            if cve_id:
                                entry["_feed_source"] = "cve_database.json"
                                temp_cves[cve_id] = entry
                                count += 1
                        temp_feeds["cve_database.json"] = {
                            "entries_count": count,
                            "path": self.fallback_path,
                            "loaded_at": datetime.now().isoformat()
                        }
                except Exception as e:
                    print(f"[!] Warning reading legacy cve_database.json: {e}")

            self._cves_by_id = temp_cves
            self._feed_metadata = temp_feeds
            self.last_sync_time = datetime.now().isoformat()
            return len(self._cves_by_id)

    def get_all_cves(self) -> List[Dict[str, Any]]:
        """Return full list of loaded CVE definitions."""
        with self._lock:
            return list(self._cves_by_id.values())

    def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Lookup CVE by identifier."""
        with self._lock:
            return self._cves_by_id.get(cve_id)

    def get_feeds_summary(self) -> Dict[str, Any]:
        """Return diagnostic summary of loaded feeds and total vulnerability entries."""
        with self._lock:
            return {
                "total_cves": len(self._cves_by_id),
                "total_feeds": len(self._feed_metadata),
                "feeds": self._feed_metadata,
                "last_sync_time": self.last_sync_time
            }

    def register_custom_cve(self, entry: Dict[str, Any], persist: bool = True) -> bool:
        """
        Dynamically register a new CVE definition for network scale-up
        (e.g., custom ESP32/microcontroller firmware vulnerabilities).
        """
        cve_id = entry.get("cve_id")
        if not cve_id:
            return False

        with self._lock:
            entry["_feed_source"] = "custom_addons.json"
            self._cves_by_id[cve_id] = entry

            if persist:
                try:
                    os.makedirs(self.feeds_dir, exist_ok=True)
                    addon_path = os.path.join(self.feeds_dir, "custom_addons.json")
                    existing = []
                    if os.path.exists(addon_path):
                        with open(addon_path, "r", encoding="utf-8") as f:
                            existing = json.load(f)
                    # Deduplicate
                    updated = [e for e in existing if e.get("cve_id") != cve_id]
                    updated.append(entry)
                    with open(addon_path, "w", encoding="utf-8") as f:
                        json.dump(updated, f, indent=2)
                except Exception as e:
                    print(f"[!] Warning persisting custom CVE {cve_id}: {e}")

            return True

    async def fetch_nvd_for_cpe_async(self, cpe_name: str, timeout: float = 8.0) -> List[Dict[str, Any]]:
        """
        Optional on-demand sync from NIST NVD 2.0 API when internet access is available.
        Maps remote NVD JSON structure to internal schema with error resilience.
        """
        try:
            import httpx
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}"
            headers = {"User-Agent": "IoT-Sec-Audit-Platform/2.0"}
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    converted = []
                    for item in vulnerabilities:
                        cve = item.get("cve", {})
                        c_id = cve.get("id")
                        metrics = cve.get("metrics", {})
                        cvss_score = 7.5
                        severity = "HIGH"
                        cvss_data = {}
                        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                            v31 = metrics["cvssMetricV31"][0].get("cvssData", {})
                            cvss_score = v31.get("baseScore", 7.5)
                            severity = v31.get("baseSeverity", "HIGH")
                            cvss_data = {"score": cvss_score, "vector": v31.get("vectorString", ""), "severity": severity}

                        desc_list = cve.get("descriptions", [])
                        desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")

                        entry = {
                            "cve_id": c_id,
                            "title": f"NVD: {c_id}",
                            "target_cpe_list": [cpe_name],
                            "cvss_score": cvss_score,
                            "cvss_v3": cvss_data,
                            "severity": severity,
                            "description": desc,
                            "remediation": "Review vendor security advisory and update firmware.",
                            "_feed_source": "nvd_live_sync"
                        }
                        converted.append(entry)
                        self.register_custom_cve(entry, persist=False)
                    return converted
        except Exception as e:
            print(f"[!] NVD live query for {cpe_name} skipped/failed: {e}")
        return []

# Global singleton
GLOBAL_CVE_MANAGER = CveManager()
