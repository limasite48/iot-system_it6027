"""
Unit Tests for Declarative IoT Policy & Hardening Checklist Engine (net-sec)
"""

import pytest
from app.audit.policy_engine import (
    PolicyEngine,
    validate_policy_document,
    PolicyValidationError,
    GLOBAL_POLICY_ENGINE
)

def test_policy_schema_validation_success():
    """Verify default policy document passes schema validation."""
    assert len(GLOBAL_POLICY_ENGINE.policies) >= 5
    assert GLOBAL_POLICY_ENGINE.version == "1.0"

def test_policy_schema_validation_rejection():
    """Verify malformed policies are rejected with PolicyValidationError."""
    malformed_doc = {
        "version": "1.0",
        "title": "Bad Policy",
        "policies": [
            {
                "id": "BAD-001",
                # missing title, standard, severity
                "remediation": "none"
            }
        ]
    }
    with pytest.raises(PolicyValidationError):
        validate_policy_document(malformed_doc)

def test_compliant_device_evaluation():
    """Verify compliant device with secure settings triggers no violations."""
    clean_device = {
        "open_ports": [443],
        "default_credentials_found": False,
        "is_open_access": False,
        "cves": []
    }
    eval_res = GLOBAL_POLICY_ENGINE.evaluate_device(clean_device)
    assert eval_res["compliant"] is True
    assert eval_res["violations_count"] == 0
    assert eval_res["quarantine_required"] is False
    assert eval_res["risk_level"] == "LOW"

def test_telnet_cleartext_policy_violation():
    """Verify open Telnet port 23 triggers IOT-POL-003 and quarantine."""
    telnet_device = {
        "open_ports": [23, 80],
        "default_credentials_found": False,
        "is_open_access": False,
        "cves": []
    }
    eval_res = GLOBAL_POLICY_ENGINE.evaluate_device(telnet_device)
    assert eval_res["compliant"] is False
    rule_ids = [v["rule_id"] for v in eval_res["violations"]]
    assert "IOT-POL-003" in rule_ids
    assert eval_res["quarantine_required"] is True

def test_default_credential_policy_violation():
    """Verify default credentials trigger IOT-POL-001 with CRITICAL severity."""
    vuln_device = {
        "open_ports": [80],
        "default_credentials_found": True,
        "is_open_access": False,
        "cves": []
    }
    eval_res = GLOBAL_POLICY_ENGINE.evaluate_device(vuln_device)
    assert eval_res["compliant"] is False
    rule_ids = [v["rule_id"] for v in eval_res["violations"]]
    assert "IOT-POL-001" in rule_ids
    assert eval_res["risk_level"] == "CRITICAL"
    assert eval_res["quarantine_required"] is True

def test_open_stream_access_violation():
    """Verify unauthenticated camera stream triggers IOT-POL-002."""
    cam_device = {
        "open_ports": [554],
        "default_credentials_found": False,
        "is_open_access": True,
        "cves": []
    }
    eval_res = GLOBAL_POLICY_ENGINE.evaluate_device(cam_device)
    assert eval_res["compliant"] is False
    rule_ids = [v["rule_id"] for v in eval_res["violations"]]
    assert "IOT-POL-002" in rule_ids
    assert eval_res["quarantine_required"] is True

def test_anonymous_mqtt_broker_violation():
    """Verify anonymous MQTT broker triggers IOT-POL-004."""
    mqtt_device = {
        "open_ports": [1883],
        "banners": {
            "mqtt_1883": {"open": True, "anonymous_allowed": True}
        },
        "default_credentials_found": False,
        "is_open_access": False,
        "cves": []
    }
    eval_res = GLOBAL_POLICY_ENGINE.evaluate_device(mqtt_device)
    assert eval_res["compliant"] is False
    rule_ids = [v["rule_id"] for v in eval_res["violations"]]
    assert "IOT-POL-004" in rule_ids
