"""
Auditor Verification & Finding Triage Workflow (net-sec)
Implements cybersecurity finding lifecycle:
  PENDING -> APPROVED (confirmed violation) / REJECTED (false positive) -> REPORTED
Ensures human auditor governance sign-off prior to publishing compliance reports.
"""

import threading
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

VALID_STATUSES = {"PENDING", "APPROVED", "REJECTED"}

class FindingRecord:
    def __init__(self, target_ip: str, finding_type: str, title: str, 
                 severity: str, details: str, remediation: str = "",
                 device_type: str = "Unknown", port: Optional[int] = None,
                 cve_id: Optional[str] = None, cpe: Optional[str] = None,
                 rule_id: Optional[str] = None, finding_id: Optional[str] = None,
                 vex_status: Optional[str] = None, vex_justification: Optional[str] = None,
                 exploitability: Optional[str] = None, ssvc_action: Optional[str] = None):
        self.finding_id = finding_id or f"fnd_{uuid.uuid4().hex[:8]}"
        self.target_ip = target_ip
        self.device_type = device_type
        self.finding_type = finding_type
        self.title = title
        self.severity = severity.upper()
        self.details = details
        self.remediation = remediation
        self.port = port
        self.cve_id = cve_id
        self.cpe = cpe
        self.rule_id = rule_id
        self.vex_status = vex_status
        self.vex_justification = vex_justification
        self.exploitability = exploitability
        self.ssvc_action = ssvc_action
        self.status = "PENDING"
        self.auditor_notes = ""
        self.reviewed_by = ""
        self.reviewed_at = None
        self.created_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "target_ip": self.target_ip,
            "device_type": self.device_type,
            "finding_type": self.finding_type,
            "title": self.title,
            "severity": self.severity,
            "details": self.details,
            "remediation": self.remediation,
            "port": self.port,
            "cve_id": self.cve_id,
            "cpe": self.cpe,
            "rule_id": self.rule_id,
            "vex_status": self.vex_status,
            "vex_justification": self.vex_justification,
            "exploitability": self.exploitability,
            "ssvc_action": self.ssvc_action,
            "status": self.status,
            "auditor_notes": self.auditor_notes,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at,
            "created_at": self.created_at
        }

class AuditorTriageManager:
    def __init__(self):
        self._lock = threading.RLock()
        self._findings: Dict[str, FindingRecord] = {}

    def _generate_fingerprint_key(self, ip: str, finding_type: str, identifier: str) -> str:
        """Deduplication key across scan cycles."""
        return f"{ip}::{finding_type}::{identifier}".lower()

    def record_finding(self, target_ip: str, finding_type: str, title: str,
                       severity: str, details: str, remediation: str = "",
                       device_type: str = "Unknown", port: Optional[int] = None,
                       cve_id: Optional[str] = None, cpe: Optional[str] = None,
                       rule_id: Optional[str] = None,
                       vex_status: Optional[str] = None, vex_justification: Optional[str] = None,
                       exploitability: Optional[str] = None, ssvc_action: Optional[str] = None) -> FindingRecord:
        """Register or update an audit finding in a thread-safe manner."""
        with self._lock:
            key_id = cve_id or rule_id or f"port_{port}" if port else title[:20]
            fp_key = self._generate_fingerprint_key(target_ip, finding_type, key_id)

            # Check if this exact finding already exists
            existing = next((f for f in self._findings.values() 
                             if self._generate_fingerprint_key(f.target_ip, f.finding_type, f.cve_id or f.rule_id or f"port_{f.port}" or f.title[:20]) == fp_key), None)
            if existing:
                # Update details but preserve existing triage status (APPROVED or REJECTED)
                existing.details = details
                existing.remediation = remediation or existing.remediation
                existing.severity = severity.upper()
                if vex_status:
                    existing.vex_status = vex_status
                if vex_justification:
                    existing.vex_justification = vex_justification
                if exploitability:
                    existing.exploitability = exploitability
                if ssvc_action:
                    existing.ssvc_action = ssvc_action
                return existing

            record = FindingRecord(
                target_ip=target_ip,
                finding_type=finding_type,
                title=title,
                severity=severity,
                details=details,
                remediation=remediation,
                device_type=device_type,
                port=port,
                cve_id=cve_id,
                cpe=cpe,
                rule_id=rule_id,
                vex_status=vex_status,
                vex_justification=vex_justification,
                exploitability=exploitability,
                ssvc_action=ssvc_action
            )
            self._findings[record.finding_id] = record
            return record

    def triage_finding(self, finding_id: str, new_status: str, 
                       auditor_notes: str = "", reviewer: str = "Security Auditor") -> Optional[Dict[str, Any]]:
        """Update finding status with auditor sign-off and notes."""
        status_clean = new_status.strip().upper()
        if status_clean not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{new_status}'. Allowed values: {VALID_STATUSES}")

        with self._lock:
            record = self._findings.get(finding_id)
            if not record:
                return None
            record.status = status_clean
            record.auditor_notes = auditor_notes
            record.reviewed_by = reviewer
            record.reviewed_at = datetime.now().isoformat()
            return record.to_dict()

    def get_findings(self, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve all findings, optionally filtered by status."""
        with self._lock:
            records = list(self._findings.values())
        if status_filter:
            records = [r for r in records if r.status == status_filter.upper()]
        # Sort by creation timestamp descending
        records.sort(key=lambda r: r.created_at, reverse=True)
        return [r.to_dict() for r in records]

    def get_triage_stats(self) -> Dict[str, int]:
        with self._lock:
            total = len(self._findings)
            pending = sum(1 for f in self._findings.values() if f.status == "PENDING")
            approved = sum(1 for f in self._findings.values() if f.status == "APPROVED")
            rejected = sum(1 for f in self._findings.values() if f.status == "REJECTED")
        return {
            "total_findings": total,
            "pending_review": pending,
            "approved_violations": approved,
            "rejected_false_positives": rejected
        }

    def clear(self):
        with self._lock:
            self._findings.clear()

GLOBAL_TRIAGE_MANAGER = AuditorTriageManager()
