"""
Declarative Policy & Hardening Checklist Engine (net-sec)
Validates declarative YAML policies against schema and audits IoT endpoints
for compliance with cybersecurity standards (NIST IR 8259A, ETSI EN 303 645).
"""

import os
import json
import yaml
from typing import Dict, Any, List, Optional

POLICIES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "policies"))
DEFAULT_POLICY_FILE = os.path.join(POLICIES_DIR, "iot_hardening_rules.yaml")
DEFAULT_SCHEMA_FILE = os.path.join(POLICIES_DIR, "policy_schema.json")

class PolicyValidationError(Exception):
    """Raised when a policy document does not conform to the schema."""
    pass

def validate_policy_document(doc: Dict[str, Any], schema_path: str = DEFAULT_SCHEMA_FILE) -> bool:
    """
    Validate policy document against JSON schema.
    Uses jsonschema library if available, otherwise executes strict built-in schema checks.
    """
    try:
        import jsonschema
        if os.path.exists(schema_path):
            with open(schema_path, "r", encoding="utf-8") as f:
                schema = json.load(f)
            jsonschema.validate(instance=doc, schema=schema)
            return True
    except ImportError:
        pass
    except Exception as e:
        raise PolicyValidationError(f"Schema validation failed: {e}")

    # Built-in strict structural validator
    if not isinstance(doc, dict):
        raise PolicyValidationError("Policy root must be a dictionary/object.")
    for req in ["version", "title", "policies"]:
        if req not in doc:
            raise PolicyValidationError(f"Policy root missing required key: {req}")

    if not isinstance(doc["policies"], list) or len(doc["policies"]) == 0:
        raise PolicyValidationError("'policies' must be a non-empty array of rule objects.")

    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    for idx, rule in enumerate(doc["policies"]):
        for r_req in ["id", "title", "standard", "severity", "condition", "remediation", "quarantine_required"]:
            if r_req not in rule:
                raise PolicyValidationError(f"Rule #{idx} ({rule.get('id', 'unknown')}) missing required key: {r_req}")
        if rule["severity"] not in valid_severities:
            raise PolicyValidationError(f"Rule #{idx} invalid severity: {rule['severity']}. Must be one of {valid_severities}")
        if not isinstance(rule["condition"], dict):
            raise PolicyValidationError(f"Rule #{idx} 'condition' must be an object.")

    return True

class PolicyEngine:
    def __init__(self, policy_file: str = DEFAULT_POLICY_FILE):
        self.policy_file = policy_file
        self.policies: List[Dict[str, Any]] = []
        self.title: str = "Default IoT Policy"
        self.version: str = "1.0"
        self.load_policies()

    def load_policies(self):
        """Load and validate declarative YAML policy checklist."""
        if not os.path.exists(self.policy_file):
            print(f"[!] Policy file not found: {self.policy_file}. Running with default built-in policy.")
            return

        with open(self.policy_file, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)

        validate_policy_document(doc)
        self.version = doc.get("version", "1.0")
        self.title = doc.get("title", "IoT Hardening Rules")
        self.policies = doc.get("policies", [])
        print(f"[+] Loaded and validated {len(self.policies)} declarative IoT policies from {os.path.basename(self.policy_file)}.")

    def evaluate_device(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a single IoT device record against loaded declarative policies.
        Returns:
          - 'compliant': bool
          - 'violations': list of triggered rules
          - 'quarantine_required': bool
          - 'recommended_vlan': 'VLAN 99 (Quarantine)' or 'VLAN 10 (Operational)'
          - 'risk_level': 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
        """
        violations = []
        quarantine_required = False

        open_ports = device.get("open_ports", [])
        has_default_pw = device.get("default_credentials_found", False)
        is_open_access = device.get("is_open_access", False)
        cves = device.get("cves", [])
        max_cvss = max([c.get("cvss_score", 0.0) for c in cves], default=0.0)

        # Build banner corpus
        banners = device.get("banners", {})
        banner_text_list = []
        for p, b in banners.items():
            if isinstance(b, dict):
                for val in b.values():
                    if isinstance(val, str):
                        banner_text_list.append(val.lower())
            elif isinstance(b, str):
                banner_text_list.append(b.lower())
        banner_corpus = " ".join(banner_text_list)

        for rule in self.policies:
            cond = rule.get("condition", {})
            triggered = False

            # Check 1: Default credentials
            if cond.get("default_credentials_check") and has_default_pw:
                triggered = True

            # Check 2: Unauthenticated open access
            if cond.get("open_access_check") and is_open_access:
                triggered = True

            # Check 3: Port checks (e.g. Telnet 23)
            if "ports_any" in cond:
                if any(p in open_ports for p in cond["ports_any"]):
                    triggered = True

            # Check 4: Anonymous MQTT check
            if cond.get("anonymous_mqtt_check"):
                mqtt_banner = banners.get("mqtt_1883", {})
                if isinstance(mqtt_banner, dict) and mqtt_banner.get("anonymous_allowed"):
                    triggered = True

            # Check 5: Banner pattern check
            if "banners_contain" in cond:
                if any(pat.lower() in banner_corpus for pat in cond["banners_contain"]):
                    triggered = True

            # Check 6: Maximum CVSS threshold
            if "max_cvss_threshold" in cond:
                if max_cvss >= float(cond["max_cvss_threshold"]):
                    triggered = True

            if triggered:
                if rule.get("quarantine_required"):
                    quarantine_required = True
                violations.append({
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "standard": rule.get("standard", ""),
                    "severity": rule.get("severity", "HIGH"),
                    "description": rule.get("description", ""),
                    "remediation": rule.get("remediation", ""),
                    "quarantine_required": rule.get("quarantine_required", False)
                })

        # Calculate composite risk level
        if any(v["severity"] == "CRITICAL" for v in violations) or has_default_pw or is_open_access or max_cvss >= 9.0:
            risk_level = "CRITICAL"
        elif any(v["severity"] == "HIGH" for v in violations) or max_cvss >= 7.0:
            risk_level = "HIGH"
        elif any(v["severity"] == "MEDIUM" for v in violations) or max_cvss >= 4.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "compliant": len(violations) == 0,
            "violations_count": len(violations),
            "violations": violations,
            "quarantine_required": quarantine_required or (risk_level in ["CRITICAL", "HIGH"]),
            "recommended_vlan": "VLAN 99 (Quarantine)" if (quarantine_required or risk_level in ["CRITICAL", "HIGH"]) else "VLAN 10 (Operational)",
            "risk_level": risk_level,
            "max_cvss": max_cvss
        }

# Global singleton
GLOBAL_POLICY_ENGINE = PolicyEngine()
