-- ============================================================
-- CLIF Hunter Agent -- ClickHouse Schema Additions
-- Run AFTER schema.sql. All tables use IF NOT EXISTS so it's
-- safe to re-run on a live cluster.
-- ============================================================

-- 1. entity_baselines -- SPC per-entity behavioral baselines
--    Updated every 60 seconds by SPCEngine.refresh_baselines().
--    Key: (hostname, metric_name). Supports 22 hosts × 6 metrics = 132 rows.

CREATE TABLE IF NOT EXISTS clif_logs.entity_baselines ON CLUSTER 'clif_cluster'
(
    hostname          String                                      CODEC(ZSTD(1)),
    metric_name       LowCardinality(String)                     CODEC(ZSTD(1)),
    window_start      DateTime64(3)                              CODEC(Delta, ZSTD(3)),
    mean_value        Float64        DEFAULT 0.0                 CODEC(ZSTD(1)),
    std_value         Float64        DEFAULT 0.0                 CODEC(ZSTD(1)),
    sample_count      UInt32         DEFAULT 0                   CODEC(ZSTD(1)),
    last_updated      DateTime64(3)  DEFAULT now64()             CODEC(ZSTD(3))
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/entity_baselines',
    '{replica}'
)
ORDER BY (hostname, metric_name, window_start)
TTL toDateTime(window_start) + INTERVAL 7 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS clif_logs.entity_baselines_dist ON CLUSTER 'clif_cluster'
AS clif_logs.entity_baselines
ENGINE = Distributed('clif_cluster', clif_logs, entity_baselines, rand());

-- ============================================================
-- 2. sigma_rule_hits -- Audit log of every Sigma rule that fires
--    Enables per-rule hit rate analytics, false-positive tuning,
--    and rule coverage reporting via /health endpoint.

CREATE TABLE IF NOT EXISTS clif_logs.sigma_rule_hits ON CLUSTER 'clif_cluster'
(
    hit_time          DateTime64(3)  DEFAULT now64()             CODEC(Delta, ZSTD(3)),
    alert_id          String                                     CODEC(ZSTD(1)),
    rule_id           String                                     CODEC(ZSTD(1)),
    rule_name         String                                     CODEC(ZSTD(1)),
    source_type       LowCardinality(String)                     CODEC(ZSTD(1)),
    hostname          String                                     CODEC(ZSTD(1)),
    severity          LowCardinality(String)                     CODEC(ZSTD(1)),
    mitre_tactic      String         DEFAULT ''                  CODEC(ZSTD(1)),
    mitre_technique   String         DEFAULT ''                  CODEC(ZSTD(1)),
    matched_events    UInt32         DEFAULT 0                   CODEC(ZSTD(1))
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/sigma_rule_hits',
    '{replica}'
)
ORDER BY (hit_time, rule_id)
TTL toDateTime(hit_time) + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS clif_logs.sigma_rule_hits_dist ON CLUSTER 'clif_cluster'
AS clif_logs.sigma_rule_hits
ENGINE = Distributed('clif_cluster', clif_logs, sigma_rule_hits, rand());

-- ============================================================
-- 3. hunter_training_data -- Self-supervised CatBoost training samples
--    Written directly by Hunter (bypasses Kafka consumer).
--    Label sources: analyst > verifier > pseudo_positive > pseudo_negative
--    TTL: 30 days (rolling window for self-supervised learning)

CREATE TABLE IF NOT EXISTS clif_logs.hunter_training_data ON CLUSTER 'clif_cluster'
(
    alert_id          String                                     CODEC(ZSTD(1)),
    feature_vector    String                                     CODEC(ZSTD(3)),
    label             UInt8          DEFAULT 0                   CODEC(ZSTD(1)),
    label_source      LowCardinality(String)                     CODEC(ZSTD(1)),
    label_confidence  Float32        DEFAULT 0.0                 CODEC(ZSTD(1)),
    created_at        DateTime64(3)  DEFAULT now64()             CODEC(Delta, ZSTD(3))
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/hunter_training_data',
    '{replica}'
)
ORDER BY (alert_id, created_at)
TTL toDateTime(created_at) + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS clif_logs.hunter_training_data_dist ON CLUSTER 'clif_cluster'
AS clif_logs.hunter_training_data
ENGINE = Distributed('clif_cluster', clif_logs, hunter_training_data, rand());

-- ============================================================
-- 4. hunter_model_health -- Drift detection metrics (written every 6h)
--    Three signals: KL divergence, PSI, Triage-anchored divergence.
--    is_drifting = 1 triggers automatic retraining.

CREATE TABLE IF NOT EXISTS clif_logs.hunter_model_health ON CLUSTER 'clif_cluster'
(
    check_time        DateTime64(3)  DEFAULT now64()             CODEC(Delta, ZSTD(3)),
    scorer_mode       LowCardinality(String)                     CODEC(ZSTD(1)),
    kl_divergence     Float32        DEFAULT 0.0                 CODEC(ZSTD(1)),
    psi_max           Float32        DEFAULT 0.0                 CODEC(ZSTD(1)),
    triage_divergence Float32        DEFAULT 0.0                 CODEC(ZSTD(1)),
    triage_bias       Float32        DEFAULT 0.0                 CODEC(ZSTD(1)),
    is_drifting       UInt8          DEFAULT 0                   CODEC(ZSTD(1)),
    sample_count      UInt32         DEFAULT 0                   CODEC(ZSTD(1)),
    alerts            String         DEFAULT ''                  CODEC(ZSTD(3))
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/hunter_model_health',
    '{replica}'
)
ORDER BY check_time
TTL toDateTime(check_time) + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS clif_logs.hunter_model_health_dist ON CLUSTER 'clif_cluster'
AS clif_logs.hunter_model_health
ENGINE = Distributed('clif_cluster', clif_logs, hunter_model_health, rand());
