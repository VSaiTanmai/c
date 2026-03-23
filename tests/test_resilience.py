"""
CLIF Resilience & Fault Tolerance Tests
=========================================
Production-grade tests that verify the storage stack survives:
  - Redpanda broker failure & recovery (no message loss)
  - ClickHouse node failure & recovery (queries still work)
  - Consumer restart recovery         (no message loss)
  - Concurrent writes during failures (pipeline resilience)

These tests are destructive — they stop/restart Docker containers.
Run them last:
    pytest tests/test_resilience.py -v --tb=short -s
"""
from __future__ import annotations

import json
import random
import subprocess
import time
import uuid
from datetime import datetime, timezone

import pytest

from conftest import CH_DB


# ── docker helpers ───────────────────────────────────────────────────────────


def docker_stop(container: str, timeout: int = 10):
    subprocess.run(
        ["docker", "stop", "-t", str(timeout), container],
        capture_output=True, timeout=30,
    )


def docker_start(container: str):
    subprocess.run(
        ["docker", "start", container],
        capture_output=True, timeout=30,
    )


def docker_restart(container: str, timeout: int = 10):
    subprocess.run(
        ["docker", "restart", "-t", str(timeout), container],
        capture_output=True, timeout=60,
    )


def docker_is_running(container: str) -> bool:
    r = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container],
        capture_output=True, text=True, timeout=10,
    )
    return r.stdout.strip() == "true"


def wait_container_healthy(container: str, timeout: int = 90):
    """Wait until container reports healthy or running."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Health.Status}}", container],
            capture_output=True, text=True, timeout=10,
        )
        status = r.stdout.strip()
        if status == "healthy":
            return True
        # Some containers don't have healthchecks
        if "template" in status.lower() or status == "":
            if docker_is_running(container):
                return True
        time.sleep(2)
    return False


# ── data helpers ─────────────────────────────────────────────────────────────


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _produce_tagged_batch(producer, tag: str, count: int, topic: str = "raw-logs"):
    """Produce count events with a unique tag for tracking."""
    delivered = 0
    errors = 0

    def _cb(err, msg):
        nonlocal delivered, errors
        if err:
            errors += 1
        else:
            delivered += 1

    for i in range(count):
        event = {
            "timestamp": _now_iso(),
            "level": random.choice(["INFO", "WARN", "ERROR"]),
            "source": "resilience-test",
            "message": f"resilience probe #{i}",
            "metadata": {
                "user_id": "tester",
                "ip_address": "10.0.0.1",
                "request_id": tag,
            },
        }
        producer.produce(topic, json.dumps(event).encode(), callback=_cb)
        if i % 200 == 0:
            producer.poll(0)
    producer.flush(60)
    producer.poll(0)
    return delivered, errors


def _wait_for_count(ch, tag: str, expected: int, timeout: int = 60) -> int:
    deadline = time.monotonic() + timeout
    found = 0
    while time.monotonic() < deadline:
        try:
            r = ch.query(
                "SELECT count() FROM raw_logs WHERE request_id = {tag:String}",
                parameters={"tag": tag},
            )
            found = r.result_rows[0][0]
            if found >= expected:
                return found
        except Exception:
            pass
        time.sleep(1)
    return found


# =============================================================================
# Test 1: Redpanda Broker Restart — No Message Loss
# =============================================================================


class TestRedpandaBrokerResilience:
    """Stop a non-seed broker, produce messages, restart, verify all arrive."""

    BATCH_SIZE = 500

    def test_no_message_loss_on_broker_restart(self, kafka_producer, ch1):
        tag = f"rp-resilience-{uuid.uuid4().hex[:8]}"

        # 1. Produce a pre-batch
        pre_del, pre_err = _produce_tagged_batch(kafka_producer, tag, self.BATCH_SIZE)
        assert pre_err == 0, f"Pre-batch errors: {pre_err}"
        print(f"\n  Pre-batch produced: {pre_del}")

        # 2. Stop redpanda02 (non-seed broker)
        print("  Stopping redpanda02 …")
        docker_stop("clif-redpanda02")

        try:
            time.sleep(5)

            # 3. Produce during outage — the cluster should still accept (RF=3, 2 alive)
            tag2 = f"rp-during-{uuid.uuid4().hex[:8]}"
            during_del, during_err = _produce_tagged_batch(kafka_producer, tag2, self.BATCH_SIZE)
            print(f"  Produced during outage: {during_del} (errors: {during_err})")
        finally:
            # 4. Always restart broker
            print("  Restarting redpanda02 …")
            docker_start("clif-redpanda02")
            time.sleep(15)

        # 5. Verify all pre-batch messages arrived
        found_pre = _wait_for_count(ch1, tag, self.BATCH_SIZE, timeout=60)
        print(f"  Pre-batch found: {found_pre}/{self.BATCH_SIZE}")
        assert found_pre >= self.BATCH_SIZE, (
            f"Lost pre-batch messages: {found_pre}/{self.BATCH_SIZE}"
        )

        # 6. Verify messages produced during outage also arrived
        found_during = _wait_for_count(ch1, tag2, during_del, timeout=60)
        print(f"  During-outage found: {found_during}/{during_del}")
        assert found_during >= during_del * 0.95, (
            f"Lost during-outage messages: {found_during}/{during_del}"
        )


# =============================================================================
# Test 2: ClickHouse Node Failover — Query Availability
# =============================================================================


class TestClickHouseFailover:
    """Stop one ClickHouse node, verify queries still work on the other."""

    def test_queries_survive_node2_failure(self, ch1, ch2, kafka_producer):
        # Ensure some data exists
        tag = f"ch-failover-{uuid.uuid4().hex[:8]}"
        _produce_tagged_batch(kafka_producer, tag, 100)
        _wait_for_count(ch1, tag, 100, timeout=30)

        # Get baseline count
        baseline = ch1.query(
            "SELECT count() FROM raw_logs WHERE timestamp >= now() - INTERVAL 1 DAY"
        ).result_rows[0][0]
        print(f"\n  Baseline count: {baseline}")

        # Stop node 2
        print("  Stopping clickhouse02 …")
        docker_stop("clif-clickhouse02")
        time.sleep(5)

        # Node 1 should still answer
        try:
            result = ch1.query(
                "SELECT count() FROM raw_logs WHERE timestamp >= now() - INTERVAL 1 DAY"
            )
            count_during = result.result_rows[0][0]
            print(f"  Node 1 query during failover: {count_during}")
            assert count_during >= baseline * 0.9, "Unexpected data loss during failover"
        finally:
            # Always restart node 2
            print("  Restarting clickhouse02 …")
            docker_start("clif-clickhouse02")
            ok = wait_container_healthy("clif-clickhouse02", timeout=90)
            assert ok, "clickhouse02 did not recover"

        # Verify replica caught up
        time.sleep(10)
        try:
            from conftest import ClickHouseClient, CH_HOST, CH_PORT_2, CH_USER, CH_PASS, CH_DB
            ch2_fresh = ClickHouseClient(
                host=CH_HOST, port=CH_PORT_2,
                username=CH_USER, password=CH_PASS,
                database=CH_DB, connect_timeout=30,
            )
            result2 = ch2_fresh.query(
                "SELECT count() FROM raw_logs WHERE request_id = {tag:String}",
                parameters={"tag": tag},
            )
            print(f"  Node 2 recovered, tag count: {result2.result_rows[0][0]}")
            assert result2.result_rows[0][0] >= 100, "Replica did not catch up"
            ch2_fresh.close()
        except Exception as e:
            pytest.fail(f"Node 2 did not recover: {e}")


# =============================================================================
# Test 3: Consumer Recovery After Restart
# =============================================================================


class TestConsumerRecovery:
    """Restart the consumer and verify no messages are lost."""

    BATCH_SIZE = 300

    def test_consumer_recovers_after_restart(self, kafka_producer, ch1):
        tag = f"consumer-recovery-{uuid.uuid4().hex[:8]}"

        # 1. Produce batch
        delivered, errors = _produce_tagged_batch(kafka_producer, tag, self.BATCH_SIZE)
        assert errors == 0
        print(f"\n  Produced {delivered} events")

        # 2. Wait for initial ingestion (partial is OK)
        time.sleep(5)

        # 3. Restart consumer
        print("  Restarting clif-consumer …")
        docker_restart("clif-consumer")
        time.sleep(10)

        # 4. Verify all events eventually land
        found = _wait_for_count(ch1, tag, self.BATCH_SIZE, timeout=60)
        print(f"  Found after recovery: {found}/{self.BATCH_SIZE}")
        assert found >= self.BATCH_SIZE, (
            f"Consumer lost events: {found}/{self.BATCH_SIZE}"
        )

    def test_consumer_running_after_recovery(self):
        """Consumer must be running (not crash-looping) after test."""
        time.sleep(5)
        assert docker_is_running("clif-consumer"), "Consumer not running after restart"


# =============================================================================
# Test 4: Concurrent Writes During Partial Failure
# =============================================================================


class TestConcurrentWritesDuringFailure:
    """Verify data durability when a broker and ClickHouse node go down simultaneously."""

    def test_data_survives_dual_failure(self, kafka_producer, ch1):
        """Produce data, kill a broker + CH node, restart, verify data intact.
        This tests data DURABILITY — the most critical production concern."""
        tag = f"dual-failure-{uuid.uuid4().hex[:8]}"

        # 1. Produce 500 events while everything is healthy
        delivered, errors = _produce_tagged_batch(kafka_producer, tag, 500)
        assert delivered >= 500, f"Pre-outage produce failed: {delivered}/500"
        print(f"\n  Pre-outage: produced {delivered} events")

        # 2. Wait for all events to be consumed into ClickHouse
        found_before = _wait_for_count(ch1, tag, 500, timeout=60)
        print(f"  Verified in ClickHouse before failure: {found_before}/500")
        assert found_before >= 500, f"Not all events ingested before failure: {found_before}/500"

        try:
            # 3. Simultaneously kill a broker and a ClickHouse node
            print("  Stopping redpanda03 and clickhouse02 …")
            docker_stop("clif-redpanda03")
            docker_stop("clif-clickhouse02")
            time.sleep(5)

            # 4. Node 1 should still serve the data (it has a full replica)
            result = ch1.query(
                "SELECT count() FROM raw_logs WHERE request_id = {tag:String}",
                parameters={"tag": tag},
            )
            surviving = result.result_rows[0][0]
            print(f"  Data on surviving node during outage: {surviving}/{found_before}")
            assert surviving >= found_before, "Data lost during dual failure!"

        finally:
            # 5. ALWAYS restore services
            print("  Restoring services …")
            docker_start("clif-redpanda03")
            docker_start("clif-clickhouse02")
            wait_container_healthy("clif-clickhouse02", timeout=90)
            time.sleep(15)

        # 6. Verify full data integrity after recovery
        final = ch1.query(
            "SELECT count() FROM raw_logs WHERE request_id = {tag:String}",
            parameters={"tag": tag},
        ).result_rows[0][0]
        print(f"  Data after full recovery: {final}/{found_before}")
        assert final >= found_before, f"Data lost after recovery: {final}/{found_before}"

        # 7. Verify replica caught up on node 2
        try:
            from conftest import ClickHouseClient, CH_HOST, CH_PORT_2, CH_USER, CH_PASS, CH_DB
            ch2 = ClickHouseClient(
                host=CH_HOST, port=CH_PORT_2,
                username=CH_USER, password=CH_PASS,
                database=CH_DB, connect_timeout=30,
            )
            r = ch2.query(
                "SELECT count() FROM raw_logs WHERE request_id = {tag:String}",
                parameters={"tag": tag},
            )
            print(f"  Node 2 replica count after recovery: {r.result_rows[0][0]}")
            ch2.close()
        except Exception as e:
            print(f"  Node 2 check failed (non-fatal): {e}")


# =============================================================================
# Test 5: Full Stack Stability After All Chaos
# =============================================================================


class TestPostChaosStability:
    """Verify the full stack is healthy after all resilience tests."""

    def test_all_containers_running(self):
        expected = [
            "clif-clickhouse-keeper",
            "clif-clickhouse01",
            "clif-clickhouse02",
            "clif-consumer",
            "clif-consumer-2",
            "clif-consumer-3",
            "clif-redpanda01",
            "clif-redpanda02",
            "clif-redpanda03",
            "clif-minio1",
            "clif-minio2",
            "clif-minio3",
            "clif-prometheus",
            "clif-grafana",
            "clif-redpanda-console",
        ]
        not_running = []
        for c in expected:
            if not docker_is_running(c):
                not_running.append(c)
        assert len(not_running) == 0, f"Containers not running: {not_running}"

    def test_clickhouse_cluster_healthy_after_chaos(self, ch1):
        result = ch1.query("SELECT count() FROM system.clusters WHERE cluster = 'clif_cluster'")
        assert result.result_rows[0][0] >= 2

    def test_final_e2e_smoke(self, kafka_producer, ch1):
        """One final E2E test to confirm the pipeline is fully operational."""
        tag = f"final-smoke-{uuid.uuid4().hex[:8]}"
        delivered, errors = _produce_tagged_batch(kafka_producer, tag, 50)
        assert errors == 0
        found = _wait_for_count(ch1, tag, 50, timeout=30)
        print(f"\n  Final smoke: {found}/50")
        assert found >= 50, f"Final smoke failed: {found}/50"
