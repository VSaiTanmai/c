-- Create missing tables for CLIF pipeline

CREATE TABLE IF NOT EXISTS clif_logs.asset_criticality ON CLUSTER 'clif_cluster'
(
    hostname_pattern    String                                     CODEC(ZSTD(1)),
    asset_class         LowCardinality(String)                     CODEC(ZSTD(1)),
    multiplier          Float32       DEFAULT 1.0                  CODEC(ZSTD(1)),
    updated_at          DateTime64(3) DEFAULT now64()              CODEC(Delta, ZSTD(3))
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/asset_criticality',
    '{replica}',
    updated_at
)
ORDER BY (hostname_pattern)
SETTINGS index_granularity = 256;

CREATE TABLE IF NOT EXISTS clif_logs.mitre_mapping_rules ON CLUSTER 'clif_cluster'
(
    rule_id           String                                       CODEC(ZSTD(1)),
    priority          UInt8         DEFAULT 100                    CODEC(ZSTD(1)),
    trigger_features  Array(String)                                CODEC(ZSTD(1)),
    trigger_threshold Float32       DEFAULT 0.0                    CODEC(ZSTD(1)),
    mitre_id          String                                       CODEC(ZSTD(1)),
    mitre_name        String                                       CODEC(ZSTD(1)),
    mitre_tactic      String        DEFAULT ''                     CODEC(ZSTD(1)),
    confidence        Enum8('LOW'=1, 'MEDIUM'=2, 'HIGH'=3)        CODEC(ZSTD(1)),
    description       String        DEFAULT ''                     CODEC(ZSTD(3)),
    updated_at        DateTime64(3) DEFAULT now64()                CODEC(Delta, ZSTD(3))
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/mitre_mapping_rules',
    '{replica}',
    updated_at
)
ORDER BY (priority, rule_id)
SETTINGS index_granularity = 256;

INSERT INTO clif_logs.mitre_mapping_rules (rule_id, priority, trigger_features, trigger_threshold, mitre_id, mitre_name, mitre_tactic, confidence, description)
VALUES
    ('brute_force',       10, ['event_freq_1m', 'template_auth'],      10.0, 'T1110', 'Brute Force',                   'credential-access',    'HIGH',   'High-freq auth failures from single entity'),
    ('lateral_movement',  20, ['unique_hosts_5m', 'template_lateral'], 3.0,  'T1021', 'Remote Services',               'lateral-movement',     'HIGH',   'Multi-host lateral movement detection'),
    ('c2_traffic',        30, ['known_malicious_ip', 'outbound'],      1.0,  'T1071', 'Application Layer Protocol',    'command-and-control',  'HIGH',   'Outbound traffic to known-malicious IP'),
    ('account_creation',  40, ['template_user_created', 'off_hours'],  1.0,  'T1136', 'Create Account',                'persistence',          'MEDIUM', 'New account creation during off-hours'),
    ('privilege_esc',     50, ['template_priv_escalation'],            1.0,  'T1068', 'Exploitation for Priv Esc',     'privilege-escalation',  'HIGH',   'Privilege escalation template detected'),
    ('data_exfil',        60, ['template_data_exfil', 'large_payload'],1.0,  'T1041', 'Exfiltration Over C2 Channel',  'exfiltration',         'HIGH',   'Data exfiltration with large payload'),
    ('zero_day',          70, ['ae_high', 'lgbm_low', 'novel_template'],0.0,'T1190', 'Exploit Public-Facing App',     'initial-access',       'MEDIUM', 'Autoencoder anomaly + unknown to LightGBM'),
    ('network_recon',     80, ['template_port_scan', 'multi_port'],    1.0,  'T1046', 'Network Service Discovery',     'discovery',            'HIGH',   'Port scan / network reconnaissance'),
    ('model_disagreement',90, ['std_dev_high'],                        0.35, 'UNKNOWN_TTP', 'Model Disagreement',      '',                     'LOW',    'High model disagreement — requires analyst review');

CREATE TABLE IF NOT EXISTS clif_logs.features_entity_freq ON CLUSTER 'clif_cluster'
(
    window         DateTime       CODEC(Delta, ZSTD(1)),
    source_ip      String         CODEC(ZSTD(1)),
    user_id        String         CODEC(ZSTD(1)),
    hostname       String         CODEC(ZSTD(1)),
    event_count    SimpleAggregateFunction(sum, UInt64),
    unique_actions AggregateFunction(uniq, String),
    min_severity   SimpleAggregateFunction(min, UInt8),
    max_severity   SimpleAggregateFunction(max, UInt8)
)
ENGINE = ReplicatedAggregatingMergeTree(
    '/clickhouse/tables/{shard}/features_entity_freq',
    '{replica}'
)
PARTITION BY toYYYYMMDD(window)
ORDER BY (source_ip, user_id, hostname, window)
TTL window + INTERVAL 7 DAY DELETE
SETTINGS index_granularity = 256;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.features_entity_freq_security_mv ON CLUSTER 'clif_cluster'
TO clif_logs.features_entity_freq
AS
SELECT
    toStartOfMinute(timestamp) AS window,
    toString(ip_address) AS source_ip,
    user_id,
    hostname,
    count() AS event_count,
    uniqState(category) AS unique_actions,
    min(severity) AS min_severity,
    max(severity) AS max_severity
FROM clif_logs.security_events
GROUP BY window, source_ip, user_id, hostname;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.features_entity_freq_network_mv ON CLUSTER 'clif_cluster'
TO clif_logs.features_entity_freq
AS
SELECT
    toStartOfMinute(timestamp) AS window,
    toString(src_ip) AS source_ip,
    '' AS user_id,
    hostname,
    count() AS event_count,
    uniqState(protocol) AS unique_actions,
    toUInt8(0) AS min_severity,
    max(toUInt8(if(is_suspicious = 1, 4, 0))) AS max_severity
FROM clif_logs.network_events
GROUP BY window, source_ip, user_id, hostname;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.features_entity_freq_process_mv ON CLUSTER 'clif_cluster'
TO clif_logs.features_entity_freq
AS
SELECT
    toStartOfMinute(timestamp) AS window,
    '' AS source_ip,
    toString(uid) AS user_id,
    hostname,
    count() AS event_count,
    uniqState(binary_path) AS unique_actions,
    toUInt8(0) AS min_severity,
    max(toUInt8(if(is_suspicious = 1, 4, 0))) AS max_severity
FROM clif_logs.process_events
GROUP BY window, source_ip, user_id, hostname;

CREATE TABLE IF NOT EXISTS clif_logs.features_template_rarity ON CLUSTER 'clif_cluster'
(
    template_id      String         CODEC(ZSTD(1)),
    source_type      LowCardinality(String)  CODEC(ZSTD(1)),
    occurrence_count SimpleAggregateFunction(sum, UInt64),
    first_seen       SimpleAggregateFunction(min, DateTime),
    last_seen        SimpleAggregateFunction(max, DateTime)
)
ENGINE = ReplicatedSummingMergeTree(
    '/clickhouse/tables/{shard}/features_template_rarity',
    '{replica}'
)
ORDER BY (template_id, source_type)
TTL last_seen + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 256;

CREATE TABLE IF NOT EXISTS clif_logs.features_entity_baseline ON CLUSTER 'clif_cluster'
(
    user_id          String         CODEC(ZSTD(1)),
    hostname         String         CODEC(ZSTD(1)),
    hour_of_day      UInt8          CODEC(ZSTD(1)),
    day_count        SimpleAggregateFunction(sum, UInt64),
    event_sum        SimpleAggregateFunction(sum, UInt64),
    event_sum_sq     SimpleAggregateFunction(sum, UInt64)
)
ENGINE = ReplicatedSummingMergeTree(
    '/clickhouse/tables/{shard}/features_entity_baseline',
    '{replica}'
)
ORDER BY (user_id, hostname, hour_of_day)
SETTINGS index_granularity = 256;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.features_entity_baseline_mv ON CLUSTER 'clif_cluster'
TO clif_logs.features_entity_baseline
AS
SELECT
    user_id,
    hostname,
    toHour(timestamp) AS hour_of_day,
    toUInt64(1) AS day_count,
    count() AS event_sum,
    count() * count() AS event_sum_sq
FROM clif_logs.security_events
GROUP BY user_id, hostname, hour_of_day;

CREATE TABLE IF NOT EXISTS clif_logs.triage_score_rollup ON CLUSTER 'clif_cluster'
(
    hour            DateTime       CODEC(Delta, ZSTD(1)),
    source_type     LowCardinality(String) CODEC(ZSTD(1)),
    action          Enum8('discard'=0, 'monitor'=1, 'escalate'=2) CODEC(ZSTD(1)),
    event_count     SimpleAggregateFunction(sum, UInt64),
    score_sum       SimpleAggregateFunction(sum, Float64),
    score_max       SimpleAggregateFunction(max, Float32)
)
ENGINE = ReplicatedAggregatingMergeTree(
    '/clickhouse/tables/{shard}/triage_score_rollup',
    '{replica}'
)
ORDER BY (hour, source_type, action)
TTL hour + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 256;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.triage_score_rollup_mv ON CLUSTER 'clif_cluster'
TO clif_logs.triage_score_rollup
AS
SELECT
    toStartOfHour(timestamp) AS hour,
    source_type,
    action,
    count() AS event_count,
    sum(toFloat64(combined_score)) AS score_sum,
    max(combined_score) AS score_max
FROM clif_logs.triage_scores
GROUP BY hour, source_type, action;

CREATE VIEW IF NOT EXISTS clif_logs.features_mv_staleness ON CLUSTER 'clif_cluster'
AS
SELECT
    table_name,
    max_ts,
    now() - toDateTime(max_ts) AS staleness_seconds,
    if(now() - toDateTime(max_ts) > 300, 1, 0) AS is_stale
FROM (
    SELECT 'features_entity_freq' AS table_name,
           max(window) AS max_ts
    FROM clif_logs.features_entity_freq
    UNION ALL
    SELECT 'features_template_rarity' AS table_name,
           max(last_seen) AS max_ts
    FROM clif_logs.features_template_rarity
    UNION ALL
    SELECT 'events_per_10s' AS table_name,
           max(ts) AS max_ts
    FROM clif_logs.events_per_10s
);

CREATE TABLE IF NOT EXISTS clif_logs.arf_replay_buffer ON CLUSTER 'clif_cluster'
(
    timestamp             DateTime       CODEC(Delta, ZSTD(1)),
    event_id              String         CODEC(ZSTD(1)),
    source_type           LowCardinality(String) CODEC(ZSTD(1)),
    hour_of_day           Float32        CODEC(ZSTD(1)),
    day_of_week           Float32        CODEC(ZSTD(1)),
    severity_numeric      Float32        CODEC(ZSTD(1)),
    source_type_numeric   Float32        CODEC(ZSTD(1)),
    src_bytes             Float32        CODEC(ZSTD(1)),
    dst_bytes             Float32        CODEC(ZSTD(1)),
    event_freq_1m         Float32        CODEC(ZSTD(1)),
    protocol              Float32        CODEC(ZSTD(1)),
    dst_port              Float32        CODEC(ZSTD(1)),
    template_rarity       Float32        CODEC(ZSTD(1)),
    threat_intel_flag     Float32        CODEC(ZSTD(1)),
    duration              Float32        CODEC(ZSTD(1)),
    same_srv_rate         Float32        CODEC(ZSTD(1)),
    diff_srv_rate         Float32        CODEC(ZSTD(1)),
    serror_rate           Float32        CODEC(ZSTD(1)),
    rerror_rate           Float32        CODEC(ZSTD(1)),
    count                 Float32        CODEC(ZSTD(1)),
    srv_count             Float32        CODEC(ZSTD(1)),
    dst_host_count        Float32        CODEC(ZSTD(1)),
    dst_host_srv_count    Float32        CODEC(ZSTD(1)),
    label                 UInt8          CODEC(ZSTD(1))
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/arf_replay_buffer',
    '{replica}'
)
ORDER BY (timestamp)
TTL timestamp + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;
