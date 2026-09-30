"""
Contextual Vulnerability Prioritizer & Exploitability Evaluator (net-sec)
Evaluates real-world exploitability, CISA SSVC decision categories, and
VEX (Vulnerability Exploitability eXchange) status based on active port reachability,
network segmentation, credential posture, and weaponization context.
"""

from typing import Dict, Any, List

def evaluate_cve_context(device: Dict[str, Any], cve: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate contextual exploitability for a single matched CVE against a target device.
    Applies Rules A, B, and C aligning with CISA SSVC and VEX standards.
    """
    open_ports = device.get("open_ports", [])
    required_ports = cve.get("required_open_ports", [])
    vlan_info = device.get("vlan", {})
    vlan_id = str(vlan_info.get("id", "")) if isinstance(vlan_info, dict) else str(vlan_info)
    is_quarantined = "99" in vlan_id
    is_cisa_kev = cve.get("cisa_kev", False)
    has_default_pw = device.get("default_credentials_found", False)
    cvss_score = float(cve.get("cvss_score", 0.0))

    # -------------------------------------------------------------------------
    # Rule A: Port Closed / Service Disabled (Safe to "Live with" / TRACK)
    # -------------------------------------------------------------------------
    if required_ports and not any(p in open_ports for p in required_ports):
        vex_status = "NOT_AFFECTED"
        vex_justification = "VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY"
        exploitability = "MITIGATED_SERVICE_DISABLED"
        ssvc_action = "TRACK"
        threat_level = "NEGLIGIBLE"
        can_live_with = True
        reason = f"Required vulnerable port(s) {required_ports} are closed on target device."

    # -------------------------------------------------------------------------
    # Rule C: Active Weaponization / Botnet Vector / Default Credentials (ACT)
    # -------------------------------------------------------------------------
    elif is_cisa_kev or (required_ports and any(p in open_ports for p in required_ports) and cvss_score >= 9.0) or has_default_pw:
        vex_status = "AFFECTED"
        vex_justification = "ACTIONABLE_EXPLOIT_AVAILABLE"
        exploitability = "ACTIVE_EXPLOITABLE"
        ssvc_action = "ACT"
        threat_level = "CRITICAL"
        can_live_with = False
        reasons = []
        if is_cisa_kev:
            reasons.append("Listed in CISA Known Exploited Vulnerabilities (KEV)")
        if cvss_score >= 9.0:
            reasons.append(f"Critical CVSS {cvss_score} on accessible open port")
        if has_default_pw:
            reasons.append("Default factory credentials active on device")
        reason = "; ".join(reasons)

    # -------------------------------------------------------------------------
    # Rule B: Compensating Quarantine VLAN Isolation (ATTEND)
    # -------------------------------------------------------------------------
    elif is_quarantined:
        vex_status = "AFFECTED"
        vex_justification = "COMPENSATING_CONTROLS_PREVENT_EXPLOITATION"
        exploitability = "MITIGATED_ISOLATED_VLAN"
        ssvc_action = "ATTEND"
        threat_level = "LOW"
        can_live_with = False
        reason = "Device resides on isolated Quarantine VLAN 99 with lateral traversal blocked."

    # -------------------------------------------------------------------------
    # Default: Conditional Exploitability (ATTEND)
    # -------------------------------------------------------------------------
    else:
        vex_status = "AFFECTED"
        vex_justification = "POTENTIALLY_EXPLOITABLE"
        exploitability = "CONDITIONAL_EXPLOITABLE"
        ssvc_action = "ATTEND"
        threat_level = cve.get("severity", "MEDIUM")
        can_live_with = False
        reason = "Vulnerability active on operational network; schedule remediation."

    return {
        "cve_id": cve.get("cve_id"),
        "title": cve.get("title"),
        "vex_status": vex_status,
        "vex_justification": vex_justification,
        "exploitability": exploitability,
        "ssvc_action": ssvc_action,
        "threat_level": threat_level,
        "can_live_with": can_live_with,
        "context_reason": reason,
        "cvss_score": cvss_score,
        "cisa_kev": is_cisa_kev
    }

def evaluate_device_context(device: Dict[str, Any], matched_cves: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluate all matched CVEs for a device and return aggregated contextual posture.
    """
    evaluated_cves = []
    actions = []
    active_exploitable = 0
    mitigated = 0

    for cve in matched_cves:
        c_eval = evaluate_cve_context(device, cve)
        # Merge back with original cve dict
        merged = {**cve, **c_eval}
        evaluated_cves.append(merged)
        actions.append(c_eval["ssvc_action"])
        if c_eval["exploitability"] == "ACTIVE_EXPLOITABLE":
            active_exploitable += 1
        elif "MITIGATED" in c_eval["exploitability"] or c_eval["can_live_with"]:
            mitigated += 1

    # Determine highest SSVC action priority
    if "ACT" in actions:
        highest_action = "ACT"
    elif "ATTEND" in actions:
        highest_action = "ATTEND"
    elif "TRACK" in actions:
        highest_action = "TRACK"
    else:
        highest_action = "NONE"

    return {
        "evaluated_cves": evaluated_cves,
        "highest_ssvc_action": highest_action,
        "active_exploitable_count": active_exploitable,
        "mitigated_count": mitigated,
        "quarantine_mandated": highest_action == "ACT",
        "can_live_with_all": len(evaluated_cves) > 0 and all(c["can_live_with"] for c in evaluated_cves)
    }
