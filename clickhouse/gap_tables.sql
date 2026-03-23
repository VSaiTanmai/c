-- Report History table: tracks all generated/downloaded reports
CREATE TABLE IF NOT EXISTS clif_logs.report_history (
    report_id UUID DEFAULT generateUUIDv4(),
    title String,
    template LowCardinality(String),
    investigation_id Nullable(UUID),
    created_at DateTime64(3) DEFAULT now64(),
    format LowCardinality(String),
    size_bytes UInt32 DEFAULT 0,
    page_count UInt16 DEFAULT 0,
    s3_key String DEFAULT '',
    created_by String DEFAULT 'system'
) ENGINE = MergeTree()
ORDER BY (created_at, report_id);

-- Distributed wrapper for cluster queries
CREATE TABLE IF NOT EXISTS clif_logs.report_history_dist AS clif_logs.report_history
ENGINE = Distributed('clif_cluster', 'clif_logs', 'report_history', rand());

-- Sigma Rules catalog: stores detection rule metadata
CREATE TABLE IF NOT EXISTS clif_logs.sigma_rules (
    rule_id String,
    rule_name String,
    severity LowCardinality(String),
    mitre_tactic LowCardinality(String),
    mitre_technique LowCardinality(String),
    description String,
    status LowCardinality(String) DEFAULT 'active',
    created_at DateTime64(3) DEFAULT now64(),
    last_fired Nullable(DateTime64(3)),
    fire_count UInt64 DEFAULT 0
) ENGINE = ReplacingMergeTree()
ORDER BY rule_id;

-- Distributed wrapper
CREATE TABLE IF NOT EXISTS clif_logs.sigma_rules_dist AS clif_logs.sigma_rules
ENGINE = Distributed('clif_cluster', 'clif_logs', 'sigma_rules', rand());

-- Feedback labels table (if not exists): stores analyst feedback for model evaluation
CREATE TABLE IF NOT EXISTS clif_logs.feedback_labels (
    event_id UUID,
    label LowCardinality(String),
    source_type LowCardinality(String) DEFAULT '',
    analyst String DEFAULT 'system',
    created_at DateTime64(3) DEFAULT now64()
) ENGINE = MergeTree()
ORDER BY (created_at, event_id);

CREATE TABLE IF NOT EXISTS clif_logs.feedback_labels_dist AS clif_logs.feedback_labels
ENGINE = Distributed('clif_cluster', 'clif_logs', 'feedback_labels', rand());

-- Seed sigma_rules with detection rules derived from Vector VRL pipeline
INSERT INTO clif_logs.sigma_rules (rule_id, rule_name, severity, mitre_tactic, mitre_technique, description, status) VALUES
('CLIF-001', 'Brute Force Authentication', 'high', 'credential-access', 'T1110', 'Multiple failed authentication attempts from same source', 'active'),
('CLIF-002', 'Suspicious PowerShell Execution', 'high', 'execution', 'T1059.001', 'PowerShell with encoded or obfuscated commands', 'active'),
('CLIF-003', 'Lateral Movement via RDP', 'high', 'lateral-movement', 'T1021.001', 'Remote Desktop connections to multiple hosts', 'active'),
('CLIF-004', 'Privilege Escalation Attempt', 'critical', 'privilege-escalation', 'T1068', 'Exploitation of vulnerability for elevated privileges', 'active'),
('CLIF-005', 'Data Exfiltration via DNS', 'critical', 'exfiltration', 'T1048.003', 'DNS tunneling or excessive DNS queries to rare domains', 'active'),
('CLIF-006', 'Malware Execution Indicator', 'critical', 'execution', 'T1204', 'Known malware hash or behavior pattern detected', 'active'),
('CLIF-007', 'Persistence via Registry', 'medium', 'persistence', 'T1547.001', 'Registry Run key modification for persistence', 'active'),
('CLIF-008', 'Reconnaissance Scan', 'medium', 'reconnaissance', 'T1046', 'Port scanning or network enumeration activity', 'active'),
('CLIF-009', 'Defense Evasion Log Clear', 'high', 'defense-evasion', 'T1070.001', 'Security event log cleared or tampered', 'active'),
('CLIF-010', 'Command and Control Beacon', 'critical', 'command-and-control', 'T1071.001', 'Periodic HTTP/S beaconing to suspicious domain', 'active'),
('CLIF-011', 'Credential Dumping', 'critical', 'credential-access', 'T1003', 'LSASS memory access or credential extraction tool', 'active'),
('CLIF-012', 'Suspicious Network Connection', 'medium', 'command-and-control', 'T1095', 'Non-standard port usage or known C2 IP connection', 'active'),
('CLIF-013', 'Account Manipulation', 'high', 'persistence', 'T1098', 'User account created or permissions modified', 'active'),
('CLIF-014', 'File-less Malware', 'high', 'defense-evasion', 'T1027', 'In-memory execution without disk artifact', 'active'),
('CLIF-015', 'SQL Injection Attempt', 'high', 'initial-access', 'T1190', 'SQL injection pattern in web request parameters', 'active');
