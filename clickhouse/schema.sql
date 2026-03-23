-- =============================================================================
-- CLIF ClickHouse Schema — Stage 3 Storage Layer
-- =============================================================================
-- Applied automatically on first start via docker-entrypoint-initdb.d
-- Engine: ReplicatedMergeTree with ZSTD compression
-- Partitioning: daily on timestamp
-- TTL: 7 days hot  ➜  30 days warm  ➜  S3 cold
-- =============================================================================

CREATE DATABASE IF NOT EXISTS clif_logs ON CLUSTER 'clif_cluster';

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. raw_logs — every ingested log line
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS clif_logs.raw_logs ON CLUSTER 'clif_cluster'
(
    event_id          UUID          DEFAULT generateUUIDv4()  CODEC(ZSTD(3)),
    timestamp         DateTime64(3) DEFAULT now64()            CODEC(Delta, ZSTD(3)),
    received_at       DateTime64(3) DEFAULT now64()            CODEC(Delta, ZSTD(3)),
    level             LowCardinality(String)                   CODEC(ZSTD(1)),
    source            LowCardinality(String)                   CODEC(ZSTD(1)),
    message           String                                   CODEC(ZSTD(3)),
    -- Structured metadata stored as a flexible map
    metadata          Map(String, String)                      CODEC(ZSTD(3)),
    -- Fields frequently used in WHERE clauses
    user_id           String        DEFAULT ''                 CODEC(ZSTD(1)),
    ip_address        IPv4          DEFAULT toIPv4('0.0.0.0')  CODEC(ZSTD(1)),
    request_id        String        DEFAULT ''                 CODEC(ZSTD(1)),
    -- Blockchain anchoring (populated asynchronously)
    anchor_tx_id      String        DEFAULT ''                 CODEC(ZSTD(1)),
    anchor_batch_hash String        DEFAULT ''                 CODEC(ZSTD(1)),

    -- Projection index for full-text search on message
    INDEX idx_message  message  TYPE tokenbf_v1(30720, 2, 0)  GRANULARITY 1,
    INDEX idx_user_id  user_id  TYPE bloom_filter(0.01)        GRANULARITY 4,
    INDEX idx_ip       ip_address TYPE minmax                  GRANULARITY 4,
    INDEX idx_req_id   request_id TYPE bloom_filter(0.01)      GRANULARITY 4
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/raw_logs',
    '{replica}'
)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (source, level, timestamp, event_id)
TTL
    toDateTime(timestamp) + INTERVAL 7  DAY TO VOLUME 'warm',
    toDateTime(timestamp) + INTERVAL 30 DAY TO VOLUME 'cold',
    toDateTime(timestamp) + INTERVAL 90 DAY DELETE
SETTINGS
    index_granularity          = 8192,
    storage_policy             = 'clif_tiered',
    merge_with_ttl_timeout     = 3600,
    ttl_only_drop_parts        = 0;


-- ─────────────────────────────────────────────────────────────────────────────
-- 2. security_events — parsed security-relevant events
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS clif_logs.security_events ON CLUSTER 'clif_cluster'
(
    event_id          UUID          DEFAULT generateUUIDv4()    CODEC(ZSTD(3)),
    timestamp         DateTime64(3) DEFAULT now64()              CODEC(Delta, ZSTD(3)),
    severity          UInt8         DEFAULT 0                    CODEC(ZSTD(1)),   -- 0=info … 4=critical
    category          LowCardinality(String)                     CODEC(ZSTD(1)),   -- e.g., auth, malware, exfil
    source            LowCardinality(String)                     CODEC(ZSTD(1)),
    description       String                                     CODEC(ZSTD(3)),
    -- Subject
    user_id           String        DEFAULT ''                   CODEC(ZSTD(1)),
    ip_address        IPv4          DEFAULT toIPv4('0.0.0.0')    CODEC(ZSTD(1)),
    hostname          String        DEFAULT ''                   CODEC(ZSTD(1)),
    -- MITRE ATT&CK mapping
    mitre_tactic      LowCardinality(String) DEFAULT ''          CODEC(ZSTD(1)),
    mitre_technique   LowCardinality(String) DEFAULT ''          CODEC(ZSTD(1)),
    -- AI enrichment
    ai_confidence     Float32       DEFAULT 0.0                  CODEC(ZSTD(1)),
    ai_explanation    String        DEFAULT ''                   CODEC(ZSTD(3)),
    -- Evidence integrity
    raw_log_event_id  UUID          DEFAULT generateUUIDv4()    CODEC(ZSTD(3)),
    anchor_tx_id      String        DEFAULT ''                   CODEC(ZSTD(1)),
    metadata          Map(String, String)                        CODEC(ZSTD(3)),

    INDEX idx_category   category     TYPE set(100)              GRANULARITY 4,
    INDEX idx_severity   severity     TYPE minmax                GRANULARITY 4,
    INDEX idx_mitre_t    mitre_tactic TYPE set(50)               GRANULARITY 4,
    INDEX idx_user_id    user_id      TYPE bloom_filter(0.01)    GRANULARITY 4,
    INDEX idx_ip         ip_address   TYPE minmax                GRANULARITY 4,
    INDEX idx_desc       description  TYPE tokenbf_v1(30720, 2, 0) GRANULARITY 1
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/security_events',
    '{replica}'
)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (category, severity, timestamp, event_id)
TTL
    toDateTime(timestamp) + INTERVAL 7  DAY TO VOLUME 'warm',
    toDateTime(timestamp) + INTERVAL 30 DAY TO VOLUME 'cold',
    toDateTime(timestamp) + INTERVAL 180 DAY DELETE
SETTINGS
    index_granularity      = 8192,
    storage_policy         = 'clif_tiered',
    merge_with_ttl_timeout = 3600;


-- ─────────────────────────────────────────────────────────────────────────────
-- 3. process_events — kernel-level process execution (Tetragon source)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS clif_logs.process_events ON CLUSTER 'clif_cluster'
(
    event_id          UUID          DEFAULT generateUUIDv4()    CODEC(ZSTD(3)),
    timestamp         DateTime64(3) DEFAULT now64()              CODEC(Delta, ZSTD(3)),
    hostname          String        DEFAULT ''                   CODEC(ZSTD(1)),
    -- Process info
    pid               UInt32        DEFAULT 0                    CODEC(Delta, ZSTD(1)),
    ppid              UInt32        DEFAULT 0                    CODEC(Delta, ZSTD(1)),
    uid               UInt32        DEFAULT 0                    CODEC(ZSTD(1)),
    gid               UInt32        DEFAULT 0                    CODEC(ZSTD(1)),
    binary_path       String        DEFAULT ''                   CODEC(ZSTD(3)),
    arguments         String        DEFAULT ''                   CODEC(ZSTD(3)),
    cwd               String        DEFAULT ''                   CODEC(ZSTD(3)),
    exit_code         Int32         DEFAULT -1                   CODEC(ZSTD(1)),
    -- Container context
    container_id      String        DEFAULT ''                   CODEC(ZSTD(1)),
    pod_name          String        DEFAULT ''                   CODEC(ZSTD(1)),
    namespace         LowCardinality(String) DEFAULT ''          CODEC(ZSTD(1)),
    -- Syscall detail
    syscall           LowCardinality(String) DEFAULT ''          CODEC(ZSTD(1)),
    -- Enrichment
    is_suspicious     UInt8         DEFAULT 0                    CODEC(ZSTD(1)),
    detection_rule    String        DEFAULT ''                   CODEC(ZSTD(1)),
    anchor_tx_id      String        DEFAULT ''                   CODEC(ZSTD(1)),
    metadata          Map(String, String)                        CODEC(ZSTD(3)),

    INDEX idx_binary    binary_path  TYPE tokenbf_v1(10240, 2, 0) GRANULARITY 1,
    INDEX idx_pid       pid          TYPE minmax                   GRANULARITY 4,
    INDEX idx_container container_id TYPE bloom_filter(0.01)       GRANULARITY 4,
    INDEX idx_ns        namespace    TYPE set(200)                 GRANULARITY 4,
    INDEX idx_syscall   syscall      TYPE set(500)                 GRANULARITY 4
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/process_events',
    '{replica}'
)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (hostname, timestamp, pid, event_id)
TTL
    toDateTime(timestamp) + INTERVAL 7  DAY TO VOLUME 'warm',
    toDateTime(timestamp) + INTERVAL 30 DAY TO VOLUME 'cold',
    toDateTime(timestamp) + INTERVAL 90 DAY DELETE
SETTINGS
    index_granularity      = 8192,
    storage_policy         = 'clif_tiered',
    merge_with_ttl_timeout = 3600;


-- ─────────────────────────────────────────────────────────────────────────────
-- 4. network_events — network connection logs
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS clif_logs.network_events ON CLUSTER 'clif_cluster'
(
    event_id          UUID          DEFAULT generateUUIDv4()    CODEC(ZSTD(3)),
    timestamp         DateTime64(3) DEFAULT now64()              CODEC(Delta, ZSTD(3)),
    hostname          String        DEFAULT ''                   CODEC(ZSTD(1)),
    -- Connection info
    src_ip            IPv4          DEFAULT toIPv4('0.0.0.0')    CODEC(ZSTD(1)),
    src_port          UInt16        DEFAULT 0                    CODEC(ZSTD(1)),
    dst_ip            IPv4          DEFAULT toIPv4('0.0.0.0')    CODEC(ZSTD(1)),
    dst_port          UInt16        DEFAULT 0                    CODEC(ZSTD(1)),
    protocol          LowCardinality(String) DEFAULT 'TCP'       CODEC(ZSTD(1)),
    direction         LowCardinality(String) DEFAULT 'outbound'  CODEC(ZSTD(1)),
    bytes_sent        UInt64        DEFAULT 0                    CODEC(Delta, ZSTD(1)),
    bytes_received    UInt64        DEFAULT 0                    CODEC(Delta, ZSTD(1)),
    duration_ms       UInt32        DEFAULT 0                    CODEC(ZSTD(1)),
    -- Process context
    pid               UInt32        DEFAULT 0                    CODEC(Delta, ZSTD(1)),
    binary_path       String        DEFAULT ''                   CODEC(ZSTD(3)),
    container_id      String        DEFAULT ''                   CODEC(ZSTD(1)),
    pod_name          String        DEFAULT ''                   CODEC(ZSTD(1)),
    namespace         LowCardinality(String) DEFAULT ''          CODEC(ZSTD(1)),
    -- Enrichment
    dns_query         String        DEFAULT ''                   CODEC(ZSTD(3)),
    geo_country       LowCardinality(String) DEFAULT ''          CODEC(ZSTD(1)),
    is_suspicious     UInt8         DEFAULT 0                    CODEC(ZSTD(1)),
    detection_rule    String        DEFAULT ''                   CODEC(ZSTD(1)),
    anchor_tx_id      String        DEFAULT ''                   CODEC(ZSTD(1)),
    metadata          Map(String, String)                        CODEC(ZSTD(3)),

    INDEX idx_src_ip    src_ip      TYPE minmax              GRANULARITY 4,
    INDEX idx_dst_ip    dst_ip      TYPE minmax              GRANULARITY 4,
    INDEX idx_dst_port  dst_port    TYPE minmax               GRANULARITY 4,
    INDEX idx_protocol  protocol    TYPE set(20)             GRANULARITY 4,
    INDEX idx_dns       dns_query   TYPE tokenbf_v1(10240, 2, 0) GRANULARITY 1,
    INDEX idx_container container_id TYPE bloom_filter(0.01)  GRANULARITY 4
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/network_events',
    '{replica}'
)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (src_ip, dst_ip, timestamp, event_id)
TTL
    toDateTime(timestamp) + INTERVAL 7  DAY TO VOLUME 'warm',
    toDateTime(timestamp) + INTERVAL 30 DAY TO VOLUME 'cold',
    toDateTime(timestamp) + INTERVAL 90 DAY DELETE
SETTINGS
    index_granularity      = 8192,
    storage_policy         = 'clif_tiered',
    merge_with_ttl_timeout = 3600;


-- ─────────────────────────────────────────────────────────────────────────────
-- 5. Materialized views for real-time aggregations
-- ─────────────────────────────────────────────────────────────────────────────

-- Events-per-minute rollup (useful for dashboard sparklines)
CREATE TABLE IF NOT EXISTS clif_logs.events_per_minute ON CLUSTER 'clif_cluster'
(
    minute       DateTime       CODEC(Delta, ZSTD(1)),
    source       LowCardinality(String) CODEC(ZSTD(1)),
    level        LowCardinality(String) CODEC(ZSTD(1)),
    event_count  SimpleAggregateFunction(sum, UInt64)
)
ENGINE = ReplicatedAggregatingMergeTree(
    '/clickhouse/tables/{shard}/events_per_minute',
    '{replica}'
)
PARTITION BY toYYYYMM(minute)
ORDER BY (minute, source, level)
TTL minute + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.events_per_minute_mv ON CLUSTER 'clif_cluster'
TO clif_logs.events_per_minute
AS
SELECT
    toStartOfMinute(timestamp) AS minute,
    source,
    level,
    count() AS event_count
FROM clif_logs.raw_logs
GROUP BY minute, source, level;


-- Security severity rollup
CREATE TABLE IF NOT EXISTS clif_logs.security_severity_hourly ON CLUSTER 'clif_cluster'
(
    hour         DateTime       CODEC(Delta, ZSTD(1)),
    category     LowCardinality(String) CODEC(ZSTD(1)),
    severity     UInt8          CODEC(ZSTD(1)),
    event_count  SimpleAggregateFunction(sum, UInt64)
)
ENGINE = ReplicatedAggregatingMergeTree(
    '/clickhouse/tables/{shard}/security_severity_hourly',
    '{replica}'
)
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, category, severity)
TTL hour + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.security_severity_hourly_mv ON CLUSTER 'clif_cluster'
TO clif_logs.security_severity_hourly
AS
SELECT
    toStartOfHour(timestamp) AS hour,
    category,
    severity,
    count() AS event_count
FROM clif_logs.security_events
GROUP BY hour, category, severity;


-- ─────────────────────────────────────────────────────────────────────────────
-- 6. Additional MVs — cover all 4 tables for events_per_minute
-- ─────────────────────────────────────────────────────────────────────────────

-- Security events → events_per_minute
CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.events_per_minute_security_mv ON CLUSTER 'clif_cluster'
TO clif_logs.events_per_minute
AS
SELECT
    toStartOfMinute(timestamp) AS minute,
    source,
    category AS level,
    count() AS event_count
FROM clif_logs.security_events
GROUP BY minute, source, level;

-- Process events → events_per_minute
CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.events_per_minute_process_mv ON CLUSTER 'clif_cluster'
TO clif_logs.events_per_minute
AS
SELECT
    toStartOfMinute(timestamp) AS minute,
    'process' AS source,
    if(is_suspicious = 1, 'SUSPICIOUS', 'NORMAL') AS level,
    count() AS event_count
FROM clif_logs.process_events
GROUP BY minute, source, level;

-- Network events → events_per_minute
CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.events_per_minute_network_mv ON CLUSTER 'clif_cluster'
TO clif_logs.events_per_minute
AS
SELECT
    toStartOfMinute(timestamp) AS minute,
    protocol AS source,
    direction AS level,
    count() AS event_count
FROM clif_logs.network_events
GROUP BY minute, source, level;


-- ─────────────────────────────────────────────────────────────────────────────
-- 6b. Fine-grained 10-second rollup for accurate sub-minute EPS measurement
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS clif_logs.events_per_10s ON CLUSTER 'clif_cluster'
(
    ts           DateTime       CODEC(Delta, ZSTD(1)),
    source       LowCardinality(String) CODEC(ZSTD(1)),
    event_count  SimpleAggregateFunction(sum, UInt64)
)
ENGINE = ReplicatedAggregatingMergeTree(
    '/clickhouse/tables/{shard}/events_per_10s',
    '{replica}'
)
ORDER BY (ts, source)
TTL ts + INTERVAL 1 HOUR DELETE
SETTINGS index_granularity = 256;

-- raw_logs → events_per_10s  (uses now() = ingestion time for accurate rate)
CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.events_per_10s_raw_mv ON CLUSTER 'clif_cluster'
TO clif_logs.events_per_10s
AS
SELECT
    toStartOfInterval(now(), INTERVAL 10 SECOND) AS ts,
    source,
    count() AS event_count
FROM clif_logs.raw_logs
GROUP BY ts, source;

-- security_events → events_per_10s  (uses now() = ingestion time)
CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.events_per_10s_security_mv ON CLUSTER 'clif_cluster'
TO clif_logs.events_per_10s
AS
SELECT
    toStartOfInterval(now(), INTERVAL 10 SECOND) AS ts,
    source,
    count() AS event_count
FROM clif_logs.security_events
GROUP BY ts, source;

-- process_events → events_per_10s  (uses now() = ingestion time)
CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.events_per_10s_process_mv ON CLUSTER 'clif_cluster'
TO clif_logs.events_per_10s
AS
SELECT
    toStartOfInterval(now(), INTERVAL 10 SECOND) AS ts,
    'process' AS source,
    count() AS event_count
FROM clif_logs.process_events
GROUP BY ts, source;

-- network_events → events_per_10s  (uses now() = ingestion time)
CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.events_per_10s_network_mv ON CLUSTER 'clif_cluster'
TO clif_logs.events_per_10s
AS
SELECT
    toStartOfInterval(now(), INTERVAL 10 SECOND) AS ts,
    protocol AS source,
    count() AS event_count
FROM clif_logs.network_events
GROUP BY ts, source;


-- ─────────────────────────────────────────────────────────────────────────────
-- 7. evidence_anchors — Merkle tree anchor records for forensic integrity
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS clif_logs.evidence_anchors ON CLUSTER 'clif_cluster'
(
    batch_id          String                                     CODEC(ZSTD(1)),
    table_name        LowCardinality(String)                     CODEC(ZSTD(1)),
    time_from         DateTime64(3)                              CODEC(Delta, ZSTD(3)),
    time_to           DateTime64(3)                              CODEC(Delta, ZSTD(3)),
    event_count       UInt64        DEFAULT 0                    CODEC(ZSTD(1)),
    merkle_root       String                                     CODEC(ZSTD(3)),
    merkle_depth      UInt8         DEFAULT 0                    CODEC(ZSTD(1)),
    leaf_hashes       Array(String)                              CODEC(ZSTD(3)),
    s3_key            String        DEFAULT ''                   CODEC(ZSTD(1)),
    s3_version_id     String        DEFAULT ''                   CODEC(ZSTD(1)),
    status            LowCardinality(String) DEFAULT 'Pending'   CODEC(ZSTD(1)),
    prev_merkle_root  String        DEFAULT ''                   CODEC(ZSTD(3)),
    created_at        DateTime64(3) DEFAULT now64()              CODEC(Delta, ZSTD(3)),

    INDEX idx_table    table_name   TYPE set(10)                 GRANULARITY 1,
    INDEX idx_status   status       TYPE set(10)                 GRANULARITY 1
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/evidence_anchors',
    '{replica}'
)
PARTITION BY toYYYYMM(created_at)
ORDER BY (table_name, time_from, batch_id)
TTL
    toDateTime(created_at) + INTERVAL 365 DAY DELETE
SETTINGS
    index_granularity = 8192;


-- ─────────────────────────────────────────────────────────────────────────────
-- 8. pipeline_metrics — producer/consumer throughput metrics for dashboard
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS clif_logs.pipeline_metrics ON CLUSTER 'clif_cluster'
(
    ts      DateTime   DEFAULT now()                              CODEC(Delta, ZSTD(1)),
    metric  LowCardinality(String)                                CODEC(ZSTD(1)),
    value   Float64    DEFAULT 0                                  CODEC(ZSTD(1))
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/pipeline_metrics',
    '{replica}'
)
ORDER BY (metric, ts)
TTL ts + INTERVAL 24 HOUR DELETE
SETTINGS index_granularity = 256;


-- =============================================================================
-- AI AGENT PIPELINE — Triage / Hunter / Verifier Infrastructure
-- =============================================================================
-- These tables support the three-agent ML pipeline:
--   Triage Agent:   Drain3 templates → ML scoring → threshold routing
--   Hunter Agent:   Deep investigation of escalated anomalies
--   Verifier Agent: Forensic verification and evidence correlation
-- =============================================================================


-- ─────────────────────────────────────────────────────────────────────────────
-- 9. allowlist — False Positive Suppression (pre-filter)
-- ─────────────────────────────────────────────────────────────────────────────
-- Checked BEFORE ML inference to suppress known-good patterns.
-- Without this, cron jobs/monitoring heartbeats cause alert storms.

CREATE TABLE IF NOT EXISTS clif_logs.allowlist ON CLUSTER 'clif_cluster'
(
    entry_type    Enum8('ip'=1, 'user'=2, 'host'=3, 'template'=4, 'source'=5)  CODEC(ZSTD(1)),
    entry_value   String                                                         CODEC(ZSTD(1)),
    reason        String        DEFAULT ''                                       CODEC(ZSTD(1)),
    added_by      String        DEFAULT 'system'                                 CODEC(ZSTD(1)),
    created_at    DateTime64(3) DEFAULT now64()                                  CODEC(Delta, ZSTD(3)),
    expires_at    Nullable(DateTime64(3))                                        CODEC(ZSTD(3)),
    active        UInt8         DEFAULT 1                                        CODEC(ZSTD(1)),

    INDEX idx_type  entry_type  TYPE set(10)  GRANULARITY 1,
    INDEX idx_val   entry_value TYPE bloom_filter(0.01)  GRANULARITY 1
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/allowlist',
    '{replica}'
)
ORDER BY (entry_type, entry_value)
SETTINGS index_granularity = 256;


-- ─────────────────────────────────────────────────────────────────────────────
-- 10. ioc_cache — Threat Intelligence IOC Cache
-- ─────────────────────────────────────────────────────────────────────────────
-- Local cache synced hourly from AbuseIPDB / VirusTotal / MISP.
-- Microsecond lookups instead of 100-500ms external API calls per event.

CREATE TABLE IF NOT EXISTS clif_logs.ioc_cache ON CLUSTER 'clif_cluster'
(
    ioc_type      Enum8('ip'=1, 'domain'=2, 'hash'=3, 'url'=4, 'email'=5)   CODEC(ZSTD(1)),
    ioc_value     String                                                       CODEC(ZSTD(1)),
    source        LowCardinality(String)                                       CODEC(ZSTD(1)),
    confidence    UInt8         DEFAULT 0                                       CODEC(ZSTD(1)),
    threat_type   LowCardinality(String) DEFAULT ''                            CODEC(ZSTD(1)),
    first_seen    DateTime64(3) DEFAULT now64()                                CODEC(Delta, ZSTD(3)),
    last_seen     DateTime64(3) DEFAULT now64()                                CODEC(Delta, ZSTD(3)),
    expires_at    DateTime64(3)                                                CODEC(Delta, ZSTD(3)),
    metadata      Map(String, String)                                          CODEC(ZSTD(3)),

    INDEX idx_ioc_type  ioc_type   TYPE set(10)             GRANULARITY 1,
    INDEX idx_ioc_val   ioc_value  TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_threat    threat_type TYPE set(50)             GRANULARITY 1
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/ioc_cache',
    '{replica}'
)
ORDER BY (ioc_type, ioc_value)
TTL toDateTime(expires_at) + INTERVAL 7 DAY DELETE
SETTINGS index_granularity = 256;


-- ─────────────────────────────────────────────────────────────────────────────
-- 11. source_thresholds — Per Source-Type Adaptive Thresholds
-- ─────────────────────────────────────────────────────────────────────────────
-- Nightly recalculated from score distributions. Prevents noisy sources
-- (Kubernetes) from dominating global thresholds.

CREATE TABLE IF NOT EXISTS clif_logs.source_thresholds ON CLUSTER 'clif_cluster'
(
    source_type             LowCardinality(String)                 CODEC(ZSTD(1)),
    suspicious_threshold    Float32       DEFAULT 0.70             CODEC(ZSTD(1)),
    anomalous_threshold     Float32       DEFAULT 0.90             CODEC(ZSTD(1)),
    baseline_window_days    UInt8         DEFAULT 7                CODEC(ZSTD(1)),
    last_recalculated       DateTime64(3) DEFAULT now64()          CODEC(Delta, ZSTD(3))
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/source_thresholds',
    '{replica}',
    last_recalculated
)
ORDER BY (source_type)
SETTINGS index_granularity = 256;

-- Seed default thresholds for common source types
-- Includes BOTH Vector-native names (winlogbeat, sysmon, auditd, etc.) AND
-- the canonical names used in training (windows_event, active_directory, etc.)
-- so that threshold lookups succeed regardless of which naming the event uses.
INSERT INTO clif_logs.source_thresholds (source_type, suspicious_threshold, anomalous_threshold)
VALUES
    -- Canonical 10 (used in training pipeline)
    ('syslog',            0.65, 0.85),
    ('windows_event',     0.70, 0.90),
    ('firewall',          0.60, 0.80),
    ('active_directory',  0.65, 0.85),
    ('dns',               0.68, 0.87),
    ('cloudtrail',        0.68, 0.87),
    ('kubernetes',        0.75, 0.92),
    ('nginx',             0.70, 0.88),
    ('netflow',           0.65, 0.85),
    ('ids_ips',           0.60, 0.80),
    -- Vector-specific aliases (used when Vector is the log shipper)
    ('winlogbeat',        0.70, 0.90),
    ('sysmon',            0.65, 0.85),
    ('auditd',            0.65, 0.85),
    ('edr-agent',         0.70, 0.90),
    ('ids-sensor',        0.60, 0.80);


-- ─────────────────────────────────────────────────────────────────────────────
-- 12. asset_criticality — Asset Criticality Multipliers
-- ─────────────────────────────────────────────────────────────────────────────
-- Payment servers get 3x score multiplier; dev boxes get 1x.

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


-- ─────────────────────────────────────────────────────────────────────────────
-- 13. triage_scores — All ML-Scored Events
-- ─────────────────────────────────────────────────────────────────────────────
-- Every event that passes through the triage agent gets a score record.
-- Scored events ≥ suspicious threshold are routed to anomaly-alerts.

CREATE TABLE IF NOT EXISTS clif_logs.triage_scores ON CLUSTER 'clif_cluster'
(
    score_id          UUID          DEFAULT generateUUIDv4()      CODEC(ZSTD(3)),
    event_id          UUID                                        CODEC(ZSTD(3)),
    timestamp         DateTime64(3) DEFAULT now64()               CODEC(Delta, ZSTD(3)),
    source_type       LowCardinality(String) DEFAULT ''           CODEC(ZSTD(1)),
    hostname          String        DEFAULT ''                    CODEC(ZSTD(1)),
    source_ip         String        DEFAULT ''                    CODEC(ZSTD(1)),
    user_id           String        DEFAULT ''                    CODEC(ZSTD(1)),
    -- Template mining
    template_id       String        DEFAULT ''                    CODEC(ZSTD(1)),
    template_rarity   Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    -- ML scores
    combined_score    Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    lgbm_score        Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    eif_score         Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    arf_score         Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    -- Confidence interval
    score_std_dev     Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    agreement         Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    ci_lower          Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    ci_upper          Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    -- Asset adjustment
    asset_multiplier  Float32       DEFAULT 1.0                   CODEC(ZSTD(1)),
    adjusted_score    Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    -- Routing decision
    action            Enum8('discard'=0, 'monitor'=1, 'escalate'=2)  CODEC(ZSTD(1)),
    -- Threat intel
    ioc_match         UInt8         DEFAULT 0                     CODEC(ZSTD(1)),
    ioc_confidence    UInt8         DEFAULT 0                     CODEC(ZSTD(1)),
    -- MITRE (populated async by SHAP worker for escalated events)
    mitre_tactic      LowCardinality(String) DEFAULT ''           CODEC(ZSTD(1)),
    mitre_technique   LowCardinality(String) DEFAULT ''           CODEC(ZSTD(1)),
    -- SHAP explainability (populated async)
    shap_top_features String        DEFAULT ''                    CODEC(ZSTD(3)),
    shap_summary      String        DEFAULT ''                    CODEC(ZSTD(3)),
    -- Feature staleness flag
    features_stale    UInt8         DEFAULT 0                     CODEC(ZSTD(1)),
    -- Model version tracking
    model_version     String        DEFAULT ''                    CODEC(ZSTD(1)),
    -- Disagreement flag
    disagreement_flag UInt8         DEFAULT 0                     CODEC(ZSTD(1)),

    INDEX idx_source_type source_type     TYPE set(50)            GRANULARITY 4,
    INDEX idx_action      action          TYPE set(5)             GRANULARITY 4,
    INDEX idx_combined    combined_score  TYPE minmax             GRANULARITY 4,
    INDEX idx_adjusted    adjusted_score  TYPE minmax             GRANULARITY 4,
    INDEX idx_template    template_id     TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_hostname    hostname        TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_ioc         ioc_match       TYPE set(2)             GRANULARITY 4,
    INDEX idx_disagree    disagreement_flag TYPE set(2)           GRANULARITY 4
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/triage_scores',
    '{replica}'
)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (source_type, action, timestamp, score_id)
TTL
    toDateTime(timestamp) + INTERVAL 7  DAY TO VOLUME 'warm',
    toDateTime(timestamp) + INTERVAL 30 DAY TO VOLUME 'cold',
    toDateTime(timestamp) + INTERVAL 90 DAY DELETE
SETTINGS
    index_granularity      = 8192,
    storage_policy         = 'clif_tiered',
    merge_with_ttl_timeout = 3600;


-- ─────────────────────────────────────────────────────────────────────────────
-- 14. hunter_investigations — Hunter Agent Results
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS clif_logs.hunter_investigations ON CLUSTER 'clif_cluster'
(
    investigation_id  UUID          DEFAULT generateUUIDv4()      CODEC(ZSTD(3)),
    alert_id          UUID                                        CODEC(ZSTD(3)),
    started_at        DateTime64(3) DEFAULT now64()               CODEC(Delta, ZSTD(3)),
    completed_at      Nullable(DateTime64(3))                     CODEC(ZSTD(3)),
    status            Enum8('pending'=0, 'running'=1, 'completed'=2, 'failed'=3, 'timeout'=4) CODEC(ZSTD(1)),
    -- Investigation context
    hostname          String        DEFAULT ''                    CODEC(ZSTD(1)),
    source_ip         String        DEFAULT ''                    CODEC(ZSTD(1)),
    user_id           String        DEFAULT ''                    CODEC(ZSTD(1)),
    trigger_score     Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    -- Findings
    severity          Enum8('info'=0, 'low'=1, 'medium'=2, 'high'=3, 'critical'=4) CODEC(ZSTD(1)),
    finding_type      LowCardinality(String) DEFAULT ''           CODEC(ZSTD(1)),
    summary           String        DEFAULT ''                    CODEC(ZSTD(3)),
    evidence_json     String        DEFAULT ''                    CODEC(ZSTD(3)),
    -- Correlated events discovered during investigation
    correlated_events Array(UUID)                                 CODEC(ZSTD(3)),
    -- MITRE mapping
    mitre_tactics     Array(String)                               CODEC(ZSTD(1)),
    mitre_techniques  Array(String)                               CODEC(ZSTD(1)),
    -- Recommendation
    recommended_action String       DEFAULT ''                    CODEC(ZSTD(3)),
    confidence        Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),

    INDEX idx_status   status       TYPE set(10)                  GRANULARITY 1,
    INDEX idx_severity severity     TYPE set(10)                  GRANULARITY 1,
    INDEX idx_host     hostname     TYPE bloom_filter(0.01)       GRANULARITY 4
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/hunter_investigations',
    '{replica}'
)
PARTITION BY toYYYYMMDD(started_at)
ORDER BY (status, started_at, investigation_id)
TTL
    toDateTime(started_at) + INTERVAL 30 DAY TO VOLUME 'warm',
    toDateTime(started_at) + INTERVAL 90 DAY TO VOLUME 'cold',
    toDateTime(started_at) + INTERVAL 365 DAY DELETE
SETTINGS
    index_granularity      = 8192,
    storage_policy         = 'clif_tiered',
    merge_with_ttl_timeout = 3600;


-- ─────────────────────────────────────────────────────────────────────────────
-- 15. verifier_results — Verifier Agent Forensic Results
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS clif_logs.verifier_results ON CLUSTER 'clif_cluster'
(
    verification_id   UUID          DEFAULT generateUUIDv4()      CODEC(ZSTD(3)),
    investigation_id  UUID                                        CODEC(ZSTD(3)),
    alert_id          UUID                                        CODEC(ZSTD(3)),
    started_at        DateTime64(3) DEFAULT now64()               CODEC(Delta, ZSTD(3)),
    completed_at      Nullable(DateTime64(3))                     CODEC(ZSTD(3)),
    status            Enum8('pending'=0, 'running'=1, 'verified'=2, 'false_positive'=3, 'inconclusive'=4, 'failed'=5) CODEC(ZSTD(1)),
    -- Verification outcome
    verdict           Enum8('true_positive'=1, 'false_positive'=2, 'inconclusive'=3) CODEC(ZSTD(1)),
    confidence        Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    -- Evidence chain verification
    evidence_verified UInt8         DEFAULT 0                     CODEC(ZSTD(1)),
    merkle_batch_ids  Array(String)                               CODEC(ZSTD(3)),
    -- Forensic details
    timeline_json     String        DEFAULT ''                    CODEC(ZSTD(3)),
    ioc_correlations  String        DEFAULT ''                    CODEC(ZSTD(3)),
    -- Final recommendation
    priority          Enum8('P4'=0, 'P3'=1, 'P2'=2, 'P1'=3)     CODEC(ZSTD(1)),
    recommended_action String       DEFAULT ''                    CODEC(ZSTD(3)),
    analyst_summary   String        DEFAULT ''                    CODEC(ZSTD(3)),
    -- Full report & attack graph
    report_narrative  String        DEFAULT ''                    CODEC(ZSTD(3)),
    evidence_json     String        DEFAULT ''                    CODEC(ZSTD(3)),

    INDEX idx_verdict  verdict      TYPE set(5)                   GRANULARITY 1,
    INDEX idx_priority priority     TYPE set(5)                   GRANULARITY 1,
    INDEX idx_status   status       TYPE set(10)                  GRANULARITY 1
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/verifier_results',
    '{replica}'
)
PARTITION BY toYYYYMMDD(started_at)
ORDER BY (verdict, started_at, verification_id)
TTL
    toDateTime(started_at) + INTERVAL 30 DAY TO VOLUME 'warm',
    toDateTime(started_at) + INTERVAL 90 DAY TO VOLUME 'cold',
    toDateTime(started_at) + INTERVAL 365 DAY DELETE
SETTINGS
    index_granularity      = 8192,
    storage_policy         = 'clif_tiered',
    merge_with_ttl_timeout = 3600;


-- ─────────────────────────────────────────────────────────────────────────────
-- 16. feedback_labels — Analyst Feedback for Model Retraining
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS clif_logs.feedback_labels ON CLUSTER 'clif_cluster'
(
    feedback_id       UUID          DEFAULT generateUUIDv4()      CODEC(ZSTD(3)),
    event_id          UUID                                        CODEC(ZSTD(3)),
    score_id          Nullable(UUID)                              CODEC(ZSTD(3)),
    timestamp         DateTime64(3) DEFAULT now64()               CODEC(Delta, ZSTD(3)),
    -- Analyst label
    label             Enum8('true_positive'=1, 'false_positive'=2, 'unknown'=3) CODEC(ZSTD(1)),
    confidence        Enum8('low'=1, 'medium'=2, 'high'=3)       CODEC(ZSTD(1)),
    analyst_id        String        DEFAULT ''                    CODEC(ZSTD(1)),
    notes             String        DEFAULT ''                    CODEC(ZSTD(3)),
    -- Original scores at time of labeling (for retraining context)
    original_combined Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    original_lgbm     Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    original_eif      Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    original_arf      Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),

    INDEX idx_label    label        TYPE set(5)                   GRANULARITY 1
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/feedback_labels',
    '{replica}'
)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (label, timestamp, feedback_id)
TTL toDateTime(timestamp) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 256;


-- ─────────────────────────────────────────────────────────────────────────────
-- 17. dead_letter_events — Pipeline Failure Tracking
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS clif_logs.dead_letter_events ON CLUSTER 'clif_cluster'
(
    dl_id             UUID          DEFAULT generateUUIDv4()      CODEC(ZSTD(3)),
    timestamp         DateTime64(3) DEFAULT now64()               CODEC(Delta, ZSTD(3)),
    failed_stage      LowCardinality(String)                      CODEC(ZSTD(1)),
    source_topic      LowCardinality(String)                      CODEC(ZSTD(1)),
    error_message     String        DEFAULT ''                    CODEC(ZSTD(3)),
    raw_payload       String        DEFAULT ''                    CODEC(ZSTD(3)),
    retry_count       UInt8         DEFAULT 0                     CODEC(ZSTD(1)),

    INDEX idx_stage    failed_stage TYPE set(20)                  GRANULARITY 1
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/dead_letter_events',
    '{replica}'
)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (failed_stage, timestamp, dl_id)
TTL toDateTime(timestamp) + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 256;


-- ─────────────────────────────────────────────────────────────────────────────
-- 18. mitre_mapping_rules — MITRE ATT&CK Mapping Rules
-- ─────────────────────────────────────────────────────────────────────────────
-- Feature-driven rules that map SHAP top features to MITRE techniques.

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

-- Seed MITRE mapping rules from the Triage Agent specification
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


-- =============================================================================
-- ML FEATURE MATERIALIZED VIEWS
-- =============================================================================
-- ClickHouse MVs replace Redis entirely. Features pre-computed at INSERT time.
-- Queries return in microseconds — no runtime feature computation needed.
-- =============================================================================


-- ─────────────────────────────────────────────────────────────────────────────
-- 19. features_entity_freq — Per-Entity Event Frequency (1-minute windows)
-- ─────────────────────────────────────────────────────────────────────────────
-- Used by LightGBM/EIF: "How active is this entity in the last N minutes?"

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

-- MV: security_events → entity frequency (security events have richest entity data)
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

-- MV: network_events → entity frequency
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

-- MV: process_events → entity frequency
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


-- ─────────────────────────────────────────────────────────────────────────────
-- 20. features_template_rarity — Drain3 Template Occurrence Counts
-- ─────────────────────────────────────────────────────────────────────────────
-- Rare templates = potentially anomalous. EIF uses this as a key feature.

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


-- ─────────────────────────────────────────────────────────────────────────────
-- 21. features_entity_baseline — Hourly Entity Behavior Baselines
-- ─────────────────────────────────────────────────────────────────────────────
-- Used by EIF: "Is this entity's behavior normal for this time of day?"
-- Captures avg and variance of event frequency per entity per hour-of-day.

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

-- MV: security_events → entity baseline (rolling hourly stats)
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


-- ─────────────────────────────────────────────────────────────────────────────
-- 22. triage_score_rollup — Hourly Score Distribution (for threshold tuning)
-- ─────────────────────────────────────────────────────────────────────────────

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


-- ─────────────────────────────────────────────────────────────────────────────
-- 23. features_mv_staleness — Feature Staleness Monitoring
-- ─────────────────────────────────────────────────────────────────────────────
-- Query this every 60s from inference service. If staleness > 300s, switch
-- to static fallback features (no ClickHouse queries needed).

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


-- ─────────────────────────────────────────────────────────────────────────────
-- 24. arf_replay_buffer — ARF Warm Restart Data Source
-- ─────────────────────────────────────────────────────────────────────────────
-- Stores the 20 canonical features + label for every scored event.
-- On container restart, the triage agent replays the last 24 h / 50 K rows
-- through ARF.learn_one() to rebuild Hoeffding trees + ADWIN detectors.
-- This avoids the River pickle bug where predict_proba_one returns constants.

CREATE TABLE IF NOT EXISTS clif_logs.arf_replay_buffer ON CLUSTER 'clif_cluster'
(
    timestamp             DateTime       CODEC(Delta, ZSTD(1)),
    event_id              String         CODEC(ZSTD(1)),
    source_type           LowCardinality(String) CODEC(ZSTD(1)),

    -- 20 canonical features in training order
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

    -- Label: derived from triage action (escalate=1, monitor/discard=0)
    label                 UInt8          CODEC(ZSTD(1))
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/arf_replay_buffer',
    '{replica}'
)
ORDER BY (timestamp)
TTL timestamp + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;
