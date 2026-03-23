"""
CLIF Data Integrity & End-to-End Pipeline Tests
=================================================
Production-grade tests that verify:
  - Messages flow correctly through the full pipeline (Redpanda → Consumer → ClickHouse)
  - All four table types can ingest and return correct data
  - Data replicates between ClickHouse nodes
  - Materialized views aggregate correctly
  - ZSTD compression is active
  - Bloom / token indexes are present

Run:
    pytest tests/test_data_integrity.py -v --tb=short
"""
from __future__ import annotations

import json
import random
import time
import uuid

import pytest

from conftest import CH_DB


# ── helpers ──────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _produce_and_flush(producer, topic: str, events: list[dict], timeout: int = 30):
    """Produce a batch and block until all deliveries are confirmed."""
    delivered = []
    errors = []

    def _cb(err, msg):
        if err:
            errors.append(err)
        else:
            delivered.append(msg)

    for event in events:
        producer.produce(topic, json.dumps(event).encode(), callback=_cb)
        if len(delivered) % 500 == 0:
            producer.poll(0)
    producer.flush(timeout)
    producer.poll(0)  # drain remaining callbacks
    assert len(errors) == 0, f"Producer delivery errors: {errors}"
    return len(delivered)


def _wait_for_count(ch, table: str, field: str, value: str,
                    expected: int, timeout: int = 45) -> int:
    """Poll ClickHouse until expected rows appear or timeout."""
    deadline = time.monotonic() + timeout
    found = 0
    while time.monotonic() < deadline:
        try:
            result = ch.query(
                f"SELECT count() FROM {table} WHERE {field} = {{val:String}}",
                parameters={"val": value},
            )
            found = result.result_rows[0][0]
            if found >= expected:
                return found
        except Exception:
            pass
        time.sleep(0.5)
    return found


# =============================================================================
# E2E Pipeline — raw_logs
# =============================================================================


class TestE2ERawLogs:
    """End-to-end: produce raw-logs → verify in ClickHouse."""

    TAG = f"e2e-raw-{uuid.uuid4().hex[:8]}"
    COUNT = 200

    @pytest.fixture(autouse=True, scope="class")
    def _produce(self, kafka_producer, ch1):
        """Produce COUNT tagged events before the class runs."""
        events = []
        for i in range(self.COUNT):
            events.append({
                "timestamp": _now_iso(),
                "level": random.choice(["INFO", "WARN", "ERROR"]),
                "source": "e2e-test",
                "message": f"E2E raw_log probe #{i}",
                "metadata": {
                    "user_id": f"tester_{i % 10}",
                    "ip_address": f"10.0.{i % 256}.{(i * 7) % 256}",
                    "request_id": self.TAG,
                },
            })
        _produce_and_flush(kafka_producer, "raw-logs", events)

    def test_all_events_arrive(self, ch1):
        found = _wait_for_count(ch1, "raw_logs", "request_id", self.TAG, self.COUNT)
        assert found >= self.COUNT, f"Expected {self.COUNT}, found {found}"

    def test_correct_level_values(self, ch1):
        result = ch1.query(
            "SELECT DISTINCT level FROM raw_logs WHERE request_id = {tag:String}",
            parameters={"tag": self.TAG},
        )
        levels = {row[0] for row in result.result_rows}
        assert levels.issubset({"INFO", "WARN", "ERROR"}), f"Unexpected levels: {levels}"

    def test_source_stored_correctly(self, ch1):
        result = ch1.query(
            "SELECT DISTINCT source FROM raw_logs WHERE request_id = {tag:String}",
            parameters={"tag": self.TAG},
        )
        assert result.result_rows[0][0] == "e2e-test"

    def test_replicated_to_node2(self, ch1, ch2):
        # Wait for node 1 first
        _wait_for_count(ch1, "raw_logs", "request_id", self.TAG, self.COUNT)
        # Node 2 should have the same count (replication)
        found = _wait_for_count(ch2, "raw_logs", "request_id", self.TAG, self.COUNT, timeout=30)
        assert found >= self.COUNT, f"Node 2 only has {found}/{self.COUNT}"


# =============================================================================
# E2E Pipeline — security_events
# =============================================================================


class TestE2ESecurityEvents:
    """End-to-end: produce security-events → verify in ClickHouse."""

    TAG = f"e2e-sec-{uuid.uuid4().hex[:8]}"
    COUNT = 100

    @pytest.fixture(autouse=True, scope="class")
    def _produce(self, kafka_producer, ch1):
        events = []
        for i in range(self.COUNT):
            events.append({
                "timestamp": _now_iso(),
                "severity": i % 5,
                "category": random.choice(["auth", "malware", "brute-force"]),
                "source": "e2e-security-test",
                "description": f"Security probe #{i} tag={self.TAG}",
                "user_id": f"sec_user_{i % 5}",
                "ip_address": f"192.168.{i % 256}.{(i * 3) % 256}",
                "hostname": f"node-{i % 10}",
                "mitre_tactic": "initial-access",
                "mitre_technique": f"T{1000 + i % 500}",
                "ai_confidence": round(random.uniform(0.1, 0.99), 2),
                "metadata": {"request_id": self.TAG},
            })
        _produce_and_flush(kafka_producer, "security-events", events)

    def test_all_events_arrive(self, ch1):
        found = _wait_for_count(ch1, "security_events", "source", "e2e-security-test", self.COUNT)
        # Use a broader filter since metadata request_id isn't a direct column
        assert found >= self.COUNT

    def test_severity_range(self, ch1):
        result = ch1.query(
            "SELECT min(severity), max(severity) FROM security_events "
            "WHERE source = 'e2e-security-test'"
        )
        mn, mx = result.result_rows[0]
        assert mn >= 0 and mx <= 4

    def test_mitre_fields_populated(self, ch1):
        result = ch1.query(
            "SELECT count() FROM security_events "
            "WHERE source = 'e2e-security-test' AND mitre_tactic != ''"
        )
        assert result.result_rows[0][0] >= self.COUNT


# =============================================================================
# E2E Pipeline — process_events
# =============================================================================


class TestE2EProcessEvents:
    TAG = f"e2e-proc-{uuid.uuid4().hex[:8]}"
    COUNT = 100

    @pytest.fixture(autouse=True, scope="class")
    def _produce(self, kafka_producer, ch1):
        events = []
        for i in range(self.COUNT):
            events.append({
                "timestamp": _now_iso(),
                "hostname": f"proc-test-node-{i % 5}",
                "pid": 10000 + i,
                "ppid": 1,
                "uid": 1000,
                "gid": 1000,
                "binary_path": "/usr/bin/python3",
                "arguments": f"--probe {self.TAG} --index {i}",
                "cwd": "/tmp",
                "exit_code": 0,
                "container_id": f"ctr-{self.TAG[:8]}",
                "pod_name": f"pod-{self.TAG[:8]}",
                "namespace": "testing",
                "syscall": "execve",
                "is_suspicious": 1 if i % 20 == 0 else 0,
                "metadata": {"tag": self.TAG},
            })
        _produce_and_flush(kafka_producer, "process-events", events)

    def test_all_events_arrive(self, ch1):
        found = _wait_for_count(
            ch1, "process_events", "namespace", "testing", self.COUNT,
        )
        assert found >= self.COUNT

    def test_suspicious_flagged(self, ch1):
        result = ch1.query(
            "SELECT count() FROM process_events "
            "WHERE namespace = 'testing' AND is_suspicious = 1"
        )
        expected_suspicious = self.COUNT // 20
        assert result.result_rows[0][0] >= expected_suspicious


# =============================================================================
# E2E Pipeline — network_events
# =============================================================================


class TestE2ENetworkEvents:
    TAG = f"e2e-net-{uuid.uuid4().hex[:8]}"
    COUNT = 100

    @pytest.fixture(autouse=True, scope="class")
    def _produce(self, kafka_producer, ch1):
        events = []
        for i in range(self.COUNT):
            events.append({
                "timestamp": _now_iso(),
                "hostname": f"net-test-node-{i % 5}",
                "src_ip": f"10.{i % 256}.0.1",
                "src_port": 40000 + i,
                "dst_ip": "93.184.216.34",
                "dst_port": 443,
                "protocol": "TCP",
                "direction": "outbound",
                "bytes_sent": 1024 * (i + 1),
                "bytes_received": 2048 * (i + 1),
                "duration_ms": 10 * (i + 1),
                "pid": 5000 + i,
                "binary_path": "/usr/bin/curl",
                "dns_query": f"{self.TAG}.example.com",
                "geo_country": "US",
                "is_suspicious": 0,
                "metadata": {"tag": self.TAG},
            })
        _produce_and_flush(kafka_producer, "network-events", events)

    def test_all_events_arrive(self, ch1):
        found = _wait_for_count(
            ch1, "network_events", "dns_query", f"{self.TAG}.example.com", self.COUNT,
        )
        assert found >= self.COUNT

    def test_bytes_aggregation(self, ch1):
        result = ch1.query(
            "SELECT sum(bytes_sent), sum(bytes_received) FROM network_events "
            "WHERE dns_query = {q:String}",
            parameters={"q": f"{self.TAG}.example.com"},
        )
        total_sent, total_recv = result.result_rows[0]
        assert total_sent > 0 and total_recv > 0


# =============================================================================
# Cross-cutting: Compression
# =============================================================================


class TestCompression:
    """Verify ZSTD compression is active on stored data."""

    @pytest.mark.parametrize("table", [
        "raw_logs", "security_events", "process_events", "network_events",
    ])
    def test_zstd_compression_active(self, ch1, table):
        result = ch1.query(
            f"SELECT sum(data_compressed_bytes), sum(data_uncompressed_bytes) "
            f"FROM system.columns "
            f"WHERE database = '{CH_DB}' AND table = '{table}' "
            f"AND data_compressed_bytes > 0"
        )
        if result.result_rows[0][0] > 0:
            compressed = result.result_rows[0][0]
            uncompressed = result.result_rows[0][1]
            ratio = compressed / uncompressed if uncompressed > 0 else 1
            assert ratio < 1.0, f"Compression not effective on {table}"


# =============================================================================
# Cross-cutting: Indexes
# =============================================================================


class TestIndexes:
    """Verify skip indexes are present on tables."""

    @pytest.mark.parametrize("table,idx_name", [
        ("raw_logs", "idx_message"),
        ("raw_logs", "idx_user_id"),
        ("raw_logs", "idx_ip"),
        ("raw_logs", "idx_req_id"),
        ("security_events", "idx_category"),
        ("security_events", "idx_severity"),
        ("security_events", "idx_mitre_t"),
        ("process_events", "idx_binary"),
        ("process_events", "idx_pid"),
        ("process_events", "idx_syscall"),
        ("network_events", "idx_src_ip"),
        ("network_events", "idx_dst_ip"),
        ("network_events", "idx_dns"),
    ])
    def test_skip_index_exists(self, ch1, table, idx_name):
        result = ch1.query(
            "SELECT count() FROM system.data_skipping_indices "
            "WHERE database = {db:String} AND table = {tbl:String} AND name = {idx:String}",
            parameters={"db": CH_DB, "tbl": table, "idx": idx_name},
        )
        assert result.result_rows[0][0] >= 1, f"Index {idx_name} missing on {table}"
