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
TTL ts + INTERVAL 1 DAY DELETE
SETTINGS index_granularity = 256;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.events_per_10s_raw_mv ON CLUSTER 'clif_cluster'
TO clif_logs.events_per_10s
AS
SELECT
    toStartOfInterval(timestamp, INTERVAL 10 SECOND) AS ts,
    source,
    count() AS event_count
FROM clif_logs.raw_logs
GROUP BY ts, source;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.events_per_10s_security_mv ON CLUSTER 'clif_cluster'
TO clif_logs.events_per_10s
AS
SELECT
    toStartOfInterval(timestamp, INTERVAL 10 SECOND) AS ts,
    source,
    count() AS event_count
FROM clif_logs.security_events
GROUP BY ts, source;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.events_per_10s_process_mv ON CLUSTER 'clif_cluster'
TO clif_logs.events_per_10s
AS
SELECT
    toStartOfInterval(timestamp, INTERVAL 10 SECOND) AS ts,
    'process' AS source,
    count() AS event_count
FROM clif_logs.process_events
GROUP BY ts, source;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.events_per_10s_network_mv ON CLUSTER 'clif_cluster'
TO clif_logs.events_per_10s
AS
SELECT
    toStartOfInterval(timestamp, INTERVAL 10 SECOND) AS ts,
    protocol AS source,
    count() AS event_count
FROM clif_logs.network_events
GROUP BY ts, source;
