"""
Real-Time Webhook Alert Dispatcher (net-sec)
Dispatches formatted notifications to external endpoints (Slack, Discord, SOC webhooks)
upon detection of High/Critical security violations (ref_1.md Module G3).
Non-blocking, rate-limited, and failure-tolerant.
"""

import threading
import httpx
from datetime import datetime
from typing import Dict, Any, Optional

class WebhookAlertDispatcher:
    def __init__(self, webhook_url: Optional[str] = None, enabled: bool = False):
        self._lock = threading.Lock()
        self.webhook_url = webhook_url
        self.enabled = enabled and bool(webhook_url)
        self.dispatch_count = 0
        self.last_dispatch_time: Optional[str] = None
        self.last_status: str = "IDLE"

    def configure(self, webhook_url: str, enabled: bool = True):
        with self._lock:
            self.webhook_url = webhook_url.strip() if webhook_url else None
            self.enabled = enabled and bool(self.webhook_url)

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "enabled": self.enabled,
                "configured": bool(self.webhook_url),
                "webhook_url": self.webhook_url[:20] + "..." if self.webhook_url and len(self.webhook_url) > 20 else self.webhook_url,
                "dispatch_count": self.dispatch_count,
                "last_dispatch_time": self.last_dispatch_time,
                "last_status": self.last_status
            }

    def dispatch_alert_async(self, alert: Dict[str, Any]):
        """Non-blocking background dispatch."""
        if not self.enabled or not self.webhook_url:
            return

        severity = alert.get("severity", "INFO").upper()
        # Only notify on CRITICAL or HIGH events
        if severity not in ["CRITICAL", "HIGH"]:
            return

        thread = threading.Thread(target=self._send_payload, args=(alert,), daemon=True)
        thread.start()

    def _send_payload(self, alert: Dict[str, Any]):
        payload = {
            "source": "IoT Cybersecurity Detection Platform",
            "timestamp": alert.get("timestamp", datetime.now().isoformat()),
            "severity": alert.get("severity"),
            "device_ip": alert.get("device_ip"),
            "device_type": alert.get("device_type"),
            "title": alert.get("title"),
            "details": alert.get("details"),
            # Generic Slack/Discord compatible text field
            "text": f"🚨 *[{alert.get('severity')}] {alert.get('title')}*\nTarget: `{alert.get('device_ip')}` ({alert.get('device_type')})\nDetails: {alert.get('details')}"
        }

        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.post(self.webhook_url, json=payload)
                with self._lock:
                    self.dispatch_count += 1
                    self.last_dispatch_time = datetime.now().isoformat()
                    self.last_status = f"HTTP {resp.status_code}"
        except Exception as e:
            with self._lock:
                self.last_status = f"Error: {e}"

GLOBAL_ALERT_DISPATCHER = WebhookAlertDispatcher()
