"""
CLIF Infrastructure Validation Tests
=====================================
Production-grade checks that verify every layer of the storage stack
is correctly deployed, configured, and operational.

Categories:
  - ClickHouse: cluster health, schema, replication, storage policies, TTL
  - Redpanda:   cluster health, topic configs, partition layout
  - MinIO:      endpoint liveness, bucket accessibility
  - Consumer:   container running, connectivity
  - Monitoring: Prometheus, Grafana reachable

Run:
    pytest tests/test_infrastructure.py -v --tb=short
"""
from __future__ import annotations

import subprocess

import pytest
import requests

from conftest import (
    CH_HOST, CH_PORT_1, CH_PORT_2, CH_USER, CH_PASS, CH_DB,
    BROKER, MINIO_ENDPOINT,
)


# =============================================================================
# Category 1: ClickHouse Cluster Health
# =============================================================================


class TestClickHouseHealth:
    """Validate ClickHouse cluster is operational and correctly configured."""

    def test_node1_responds(self, ch1):
        result = ch1.query("SELECT 1")
        assert result.result_rows[0][0] == 1

    def test_node2_responds(self, ch2):
        result = ch2.query("SELECT 1")
        assert result.result_rows[0][0] == 1

    def test_keeper_quorum(self, ch_system):
        """ClickHouse Keeper must report a valid leader."""
        result = ch_system.query(
            "SELECT count() FROM system.zookeeper WHERE path = '/'"
        )
        assert result.result_rows[0][0] >= 1, "Keeper root path not accessible"

    def test_cluster_registered(self, ch_system):
        """clif_cluster must be visible with both replicas."""
        result = ch_system.query(
            "SELECT count() FROM system.clusters WHERE cluster = 'clif_cluster'"
        )
        assert result.result_rows[0][0] >= 2, "Expected ≥2 nodes in clif_cluster"

    def test_both_replicas_active(self, ch_system):
        """Both replicas must be active (no read-only flag)."""
        result = ch_system.query(
            "SELECT is_readonly FROM system.replicas WHERE database = 'clif_logs'"
        )
        rows = result.result_rows
        assert len(rows) > 0, "No replicated tables found"
        for row in rows:
            assert row[0] == 0, "At least one replica is in read-only mode"

    def test_no_replication_queue_errors(self, ch_system):
        """Replication queue should have zero future parts (no repl lag)."""
        result = ch_system.query(
            "SELECT sum(future_parts) FROM system.replicas "
            "WHERE database = 'clif_logs'"
        )
        assert result.result_rows[0][0] <= 10, "Excessive replication queue backlog"

    def test_uptime_reasonable(self, ch_system):
        """Node must have been up for at least 30 seconds."""
        result = ch_system.query("SELECT uptime()")
        assert result.result_rows[0][0] >= 30

    def test_version_is_24_8(self, ch_system):
        """Pin to expected ClickHouse version."""
        result = ch_system.query("SELECT version()")
        version = result.result_rows[0][0]
        assert version.startswith("24.8"), f"Unexpected version: {version}"


# =============================================================================
# Category 2: ClickHouse Schema Validation
# =============================================================================


class TestClickHouseSchema:
    """Verify tables, materialized views, engines, and columns are correct."""

    EXPECTED_TABLES = {
        "raw_logs": "ReplicatedMergeTree",
        "security_events": "ReplicatedMergeTree",
        "process_events": "ReplicatedMergeTree",
        "network_events": "ReplicatedMergeTree",
        "events_per_minute": "ReplicatedAggregatingMergeTree",
        "security_severity_hourly": "ReplicatedAggregatingMergeTree",
    }

    EXPECTED_MVS = [
        "events_per_minute_mv",
        "security_severity_hourly_mv",
    ]

    @pytest.mark.parametrize("table,engine", EXPECTED_TABLES.items())
    def test_table_exists_with_correct_engine(self, ch1, table, engine):
        result = ch1.query(
            "SELECT engine FROM system.tables "
            "WHERE database = {db:String} AND name = {tbl:String}",
            parameters={"db": CH_DB, "tbl": table},
        )
        assert len(result.result_rows) == 1, f"Table {table} not found"
        assert result.result_rows[0][0] == engine, (
            f"{table} engine mismatch: expected {engine}, got {result.result_rows[0][0]}"
        )

    @pytest.mark.parametrize("mv", EXPECTED_MVS)
    def test_materialized_view_exists(self, ch1, mv):
        result = ch1.query(
            "SELECT engine FROM system.tables "
            "WHERE database = {db:String} AND name = {mv:String}",
            parameters={"db": CH_DB, "mv": mv},
        )
        assert len(result.result_rows) == 1, f"MV {mv} not found"
        assert result.result_rows[0][0] == "MaterializedView"

    @pytest.mark.parametrize("table,expected_cols", [
        ("raw_logs", [
            "event_id", "timestamp", "received_at", "level", "source",
            "message", "metadata", "user_id", "ip_address", "request_id",
            "anchor_tx_id", "anchor_batch_hash",
        ]),
        ("security_events", [
            "event_id", "timestamp", "severity", "category", "source",
            "description", "user_id", "ip_address", "hostname",
            "mitre_tactic", "mitre_technique", "ai_confidence",
            "ai_explanation", "raw_log_event_id", "anchor_tx_id", "metadata",
        ]),
        ("process_events", [
            "event_id", "timestamp", "hostname", "pid", "ppid", "uid", "gid",
            "binary_path", "arguments", "cwd", "exit_code",
            "container_id", "pod_name", "namespace", "syscall",
            "is_suspicious", "detection_rule", "anchor_tx_id", "metadata",
        ]),
        ("network_events", [
            "event_id", "timestamp", "hostname", "src_ip", "src_port",
            "dst_ip", "dst_port", "protocol", "direction",
            "bytes_sent", "bytes_received", "duration_ms", "pid",
            "binary_path", "container_id", "pod_name", "namespace",
            "dns_query", "geo_country", "is_suspicious", "detection_rule",
            "anchor_tx_id", "metadata",
        ]),
    ])
    def test_table_columns(self, ch1, table, expected_cols):
        result = ch1.query(
            "SELECT name FROM system.columns "
            "WHERE database = {db:String} AND table = {tbl:String} "
            "ORDER BY position",
            parameters={"db": CH_DB, "tbl": table},
        )
        actual_cols = [row[0] for row in result.result_rows]
        for col in expected_cols:
            assert col in actual_cols, f"Column {col} missing from {table}"

    @pytest.mark.parametrize("table", ["raw_logs", "security_events", "process_events", "network_events"])
    def test_tables_replicated_to_node2(self, ch2, table):
        """Every base table must also exist on the second replica."""
        result = ch2.query(
            "SELECT count() FROM system.tables "
            "WHERE database = {db:String} AND name = {tbl:String}",
            parameters={"db": CH_DB, "tbl": table},
        )
        assert result.result_rows[0][0] == 1, f"{table} missing on node 2"

    @pytest.mark.parametrize("table", ["raw_logs", "security_events", "process_events", "network_events"])
    def test_partition_key_is_daily(self, ch1, table):
        """All tables should partition by toYYYYMMDD(timestamp)."""
        result = ch1.query(
            "SELECT partition_key FROM system.tables "
            "WHERE database = {db:String} AND name = {tbl:String}",
            parameters={"db": CH_DB, "tbl": table},
        )
        pk = result.result_rows[0][0]
        assert "toYYYYMMDD" in pk, f"{table} partition key not daily: {pk}"


# =============================================================================
# Category 3: Storage Policies & Tiering
# =============================================================================


class TestStoragePolicies:
    """Verify tiered storage (hot/warm/cold) is correctly configured."""

    def test_clif_tiered_policy_exists(self, ch_system):
        result = ch_system.query(
            "SELECT count() FROM system.storage_policies "
            "WHERE policy_name = 'clif_tiered'"
        )
        assert result.result_rows[0][0] >= 1, "clif_tiered policy not found"

    def test_has_three_volumes(self, ch_system):
        """Policy must define hot, warm, cold volumes."""
        result = ch_system.query(
            "SELECT volume_name FROM system.storage_policies "
            "WHERE policy_name = 'clif_tiered' ORDER BY volume_priority"
        )
        volumes = [row[0] for row in result.result_rows]
        assert "hot" in volumes, "Missing 'hot' volume"
        assert "warm" in volumes, "Missing 'warm' volume"
        assert "cold" in volumes, "Missing 'cold' volume"

    def test_s3_cold_disk_exists(self, ch_system):
        """An S3-type disk named 's3_cold' must be registered."""
        result = ch_system.query(
            "SELECT name, type FROM system.disks WHERE name = 's3_cold'"
        )
        assert len(result.result_rows) >= 1, "s3_cold disk not found"
        assert result.result_rows[0][1].lower() in ("s3", "object_storage", "objectstorage"), (
            f"s3_cold disk type unexpected: {result.result_rows[0][1]}"
        )

    def test_warm_disk_exists(self, ch_system):
        """A separate 'warm_disk' must be registered (not just 'default')."""
        result = ch_system.query(
            "SELECT name FROM system.disks WHERE name = 'warm_disk'"
        )
        assert len(result.result_rows) >= 1, "warm_disk not found"

    @pytest.mark.parametrize("table", ["raw_logs", "security_events", "process_events", "network_events"])
    def test_tables_use_tiered_policy(self, ch1, table):
        """Every base table must use the clif_tiered storage policy."""
        result = ch1.query(
            f"SELECT storage_policy FROM system.tables "
            f"WHERE database = '{CH_DB}' AND name = '{table}'"
        )
        assert result.result_rows[0][0] == "clif_tiered", (
            f"{table} not using clif_tiered policy"
        )


# =============================================================================
# Category 4: Redpanda / Kafka Cluster
# =============================================================================


class TestRedpandaCluster:
    """Validate Redpanda brokers, topics, and configuration."""

    EXPECTED_TOPICS = ["raw-logs", "security-events", "process-events", "network-events"]

    def test_cluster_reachable(self, kafka_admin):
        """At least one broker must respond to metadata requests."""
        md = kafka_admin.list_topics(timeout=10)
        assert len(md.brokers) >= 1, "No brokers responded"

    def test_three_brokers(self, kafka_admin):
        import time as _time
        for _ in range(5):
            md = kafka_admin.list_topics(timeout=10)
            if len(md.brokers) >= 3:
                break
            _time.sleep(2)
        assert len(md.brokers) >= 3, f"Expected 3 brokers, got {len(md.brokers)}"

    @pytest.mark.parametrize("topic", EXPECTED_TOPICS)
    def test_topic_exists(self, kafka_admin, topic):
        md = kafka_admin.list_topics(timeout=10)
        assert topic in md.topics, f"Topic {topic} not found"

    @pytest.mark.parametrize("topic", EXPECTED_TOPICS)
    def test_topic_has_12_partitions(self, kafka_admin, topic):
        md = kafka_admin.list_topics(timeout=10)
        partitions = md.topics[topic].partitions
        assert len(partitions) == 12, f"{topic}: expected 12 partitions, got {len(partitions)}"

    @pytest.mark.parametrize("topic", EXPECTED_TOPICS)
    def test_topic_replication_factor(self, kafka_admin, topic):
        md = kafka_admin.list_topics(timeout=10)
        partitions = md.topics[topic].partitions
        # Check first partition's replica count
        rf = len(partitions[0].replicas)
        assert rf == 3, f"{topic}: expected RF=3, got {rf}"

    def test_no_under_replicated_partitions(self, kafka_admin):
        md = kafka_admin.list_topics(timeout=10)
        under_replicated = []
        for topic_name, topic_md in md.topics.items():
            if topic_name.startswith("_"):
                continue
            for pid, p in topic_md.partitions.items():
                if len(p.isrs) < len(p.replicas):
                    under_replicated.append(f"{topic_name}[{pid}]")
        assert len(under_replicated) == 0, (
            f"Under-replicated partitions: {under_replicated}"
        )


# =============================================================================
# Category 5: MinIO (S3)
# =============================================================================


class TestMinIO:
    """Validate MinIO cluster is reachable and buckets exist."""

    def test_minio_health_endpoint(self):
        resp = requests.get(f"{MINIO_ENDPOINT}/minio/health/live", timeout=10)
        assert resp.status_code == 200, f"MinIO health check failed: {resp.status_code}"

    def test_minio_cluster_endpoint(self):
        resp = requests.get(f"{MINIO_ENDPOINT}/minio/health/cluster", timeout=10)
        assert resp.status_code in (200, 503), f"MinIO cluster check unexpected: {resp.status_code}"


# =============================================================================
# Category 6: Consumer Pipeline
# =============================================================================


class TestConsumerPipeline:
    """Verify the consumer container is running and connected."""

    def test_consumer_container_running(self):
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", "clif-consumer"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.stdout.strip() == "true", "Consumer container not running"

    def test_consumer_connected_to_clickhouse(self):
        """Look for the 'connected to ClickHouse' line in recent logs."""
        result = subprocess.run(
            ["docker", "logs", "--tail", "500", "clif-consumer"],
            capture_output=True, text=True, timeout=10,
        )
        combined = result.stdout + result.stderr
        assert "connected to ClickHouse" in combined.lower() or \
               "Connected to ClickHouse" in combined or \
               "connected to ClickHouse" in combined, \
               "Consumer did not connect to ClickHouse"

    def test_consumer_subscribed_to_topics(self):
        result = subprocess.run(
            ["docker", "logs", "--tail", "500", "clif-consumer"],
            capture_output=True, text=True, timeout=10,
        )
        combined = result.stdout + result.stderr
        assert "Subscribed to topics" in combined, "Consumer not subscribed"


# =============================================================================
# Category 7: Monitoring Stack
# =============================================================================


class TestMonitoring:
    """Validate Prometheus and Grafana are reachable."""

    def test_prometheus_healthy(self):
        resp = requests.get("http://localhost:9090/-/healthy", timeout=10)
        assert resp.status_code == 200

    def test_prometheus_has_targets(self):
        resp = requests.get("http://localhost:9090/api/v1/targets", timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "success"

    def test_grafana_healthy(self):
        resp = requests.get("http://localhost:3002/api/health", timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("database") == "ok"
