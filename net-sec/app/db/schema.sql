-- IoT Cybersecurity Policy and Governance (IT6027)
-- Relational Database Schema for Insecure IoT Device Detection Platform
-- Implements audit durability, scan history, device inventory, and auditor triage records.

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target_cidr TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    status TEXT NOT NULL,
    stage TEXT NOT NULL,
    devices_discovered INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
    ip TEXT PRIMARY KEY,
    mac TEXT,
    vendor TEXT,
    model TEXT,
    device_type TEXT,
    vlan_id INTEGER,
    vlan_name TEXT,
    risk_level TEXT,
    default_credentials_found INTEGER DEFAULT 0,
    is_open_access INTEGER DEFAULT 0,
    is_online INTEGER DEFAULT 1,
    raw_json TEXT,
    last_audited TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service TEXT,
    banner TEXT,
    FOREIGN KEY (ip) REFERENCES devices(ip) ON DELETE CASCADE,
    UNIQUE(ip, port, protocol)
);

CREATE TABLE IF NOT EXISTS cve_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    ip TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    title TEXT,
    severity TEXT,
    cvss_score REAL,
    cpe TEXT,
    vex_status TEXT,
    exploitability TEXT,
    ssvc_action TEXT,
    description TEXT,
    remediation TEXT,
    FOREIGN KEY (ip) REFERENCES devices(ip) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS triage_records (
    finding_id TEXT PRIMARY KEY,
    target_ip TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    port INTEGER,
    cve_id TEXT,
    rule_id TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    auditor_notes TEXT DEFAULT '',
    reviewed_by TEXT DEFAULT '',
    reviewed_at TEXT,
    created_at TEXT NOT NULL,
    details TEXT,
    remediation TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    device_ip TEXT,
    device_type TEXT,
    title TEXT NOT NULL,
    details TEXT
);

-- Indices for rapid query performance
CREATE INDEX IF NOT EXISTS idx_devices_risk ON devices(risk_level);
CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type);
CREATE INDEX IF NOT EXISTS idx_device_ports_ip ON device_ports(ip);
CREATE INDEX IF NOT EXISTS idx_cve_findings_ip ON cve_findings(ip);
CREATE INDEX IF NOT EXISTS idx_triage_status ON triage_records(status);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
