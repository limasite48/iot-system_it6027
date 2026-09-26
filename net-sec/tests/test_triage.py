"""
Unit Tests for Auditor Verification & Finding Triage Workflow (net-sec)
"""

import pytest
from app.audit.triage import AuditorTriageManager

def test_finding_creation_defaults_to_pending():
    mgr = AuditorTriageManager()
    f = mgr.record_finding(
        target_ip="192.168.137.50",
        finding_type="DEFAULT_CREDENTIAL",
        title="Default Password Violation",
        severity="CRITICAL",
        details="Port 23 accepted admin:admin",
        port=23
    )
    assert f.status == "PENDING"
    assert f.target_ip == "192.168.137.50"
    assert f.severity == "CRITICAL"
    stats = mgr.get_triage_stats()
    assert stats["total_findings"] == 1
    assert stats["pending_review"] == 1

def test_triage_to_approved_and_rejected():
    mgr = AuditorTriageManager()
    f1 = mgr.record_finding("192.168.137.50", "CVE", "CVE-2020-25078", "CRITICAL", "Desc 1", cve_id="CVE-2020-25078")
    f2 = mgr.record_finding("192.168.137.51", "POLICY_VIOLATION", "Telnet Cleartext", "HIGH", "Desc 2", rule_id="IOT-POL-003")

    # Approve f1
    up1 = mgr.triage_finding(f1.finding_id, "APPROVED", auditor_notes="Verified against device firmware 1.14.04", reviewer="Auditor Alice")
    assert up1["status"] == "APPROVED"
    assert up1["auditor_notes"] == "Verified against device firmware 1.14.04"
    assert up1["reviewed_by"] == "Auditor Alice"

    # Reject f2 (e.g. accepted lab test)
    up2 = mgr.triage_finding(f2.finding_id, "REJECTED", auditor_notes="Isolated test environment, risk accepted", reviewer="Auditor Bob")
    assert up2["status"] == "REJECTED"

    stats = mgr.get_triage_stats()
    assert stats["total_findings"] == 2
    assert stats["pending_review"] == 0
    assert stats["approved_violations"] == 1
    assert stats["rejected_false_positives"] == 1

def test_triage_invalid_status_rejection():
    mgr = AuditorTriageManager()
    f = mgr.record_finding("192.168.137.50", "CVE", "CVE-Test", "HIGH", "Desc")
    with pytest.raises(ValueError):
        mgr.triage_finding(f.finding_id, "INVALID_STATUS")

def test_duplicate_finding_preserves_triage_status():
    mgr = AuditorTriageManager()
    f = mgr.record_finding("192.168.137.50", "CVE", "CVE-2020-25078", "CRITICAL", "Desc 1", cve_id="CVE-2020-25078")
    mgr.triage_finding(f.finding_id, "APPROVED", auditor_notes="Confirmed true positive")

    # Next scan cycle records the same finding
    f2 = mgr.record_finding("192.168.137.50", "CVE", "CVE-2020-25078", "CRITICAL", "Desc Updated", cve_id="CVE-2020-25078")
    assert f2.finding_id == f.finding_id
    assert f2.status == "APPROVED"
    assert f2.auditor_notes == "Confirmed true positive"
