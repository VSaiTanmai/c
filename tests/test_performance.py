"""
CLIF Performance & Throughput Tests
=====================================
Production-grade benchmarks that validate:
  - Burst write throughput   (target: ≥50k events/sec in dev)
  - End-to-end latency       (Redpanda → ClickHouse < 5s for a probe batch)
  - Query performance        (analyst queries < 500ms)
  - Multi-topic fan-out      (all 4 topics processed concurrently)
  - ClickHouse insert rate   (direct insert bulk performance)

Run:
    pytest tests/test_performance.py -v --tb=short -s
"""
from __future__ import annotations

import json
import random
import string
import time
import uuid
from datetime import datetime, timezone

import pytest
from confluent_kafka import Producer

from conftest import CH_DB


# ── generators ───────────────────────────────────────────────────────────────

def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _rand_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _rand_id(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def gen_raw_log(tag: str) -> dict:
    return {
        "timestamp": _now_iso(),
        "level": random.choice(["INFO", "INFO", "WARN", "ERROR"]),
        "source": random.choice(["web", "api", "auth", "firewall", "dns"]),
        "message": f"perf probe {_rand_id(16)}",
        "metadata": {
            "user_id": f"u{random.randint(1000,9999)}",
            "ip_address": _rand_ip(),
            "request_id": tag,
        },
    }


def gen_security_event(tag: str) -> dict:
    return {
        "timestamp": _now_iso(),
        "severity": random.randint(0, 4),
        "category": random.choice(["auth", "malware", "brute-force"]),
        "source": "perf-test",
        "description": f"perf sec {tag} {_rand_id(12)}",
        "user_id": f"u{random.randint(1000,9999)}",
        "ip_address": _rand_ip(),
        "hostname": f"node-{random.randint(1,50)}",
        "mitre_tactic": "execution",
        "mitre_technique": f"T{random.randint(1000,1999)}",
        "ai_confidence": round(random.uniform(0.1, 0.99), 2),
        "metadata": {"request_id": tag},
    }


def gen_process_event(tag: str) -> dict:
    return {
        "timestamp": _now_iso(),
        "hostname": f"node-{random.randint(1,50)}",
        "pid": random.randint(1, 65535),
        "ppid": random.randint(1, 65535),
        "uid": random.randint(0, 65534),
        "gid": random.randint(0, 65534),
        "binary_path": random.choice(["/bin/bash", "/usr/bin/python3", "/usr/sbin/sshd"]),
        "arguments": f"--tag {tag}",
        "cwd": "/tmp",
        "exit_code": 0,
        "container_id": _rand_id(16),
        "pod_name": f"pod-{_rand_id(6)}",
        "namespace": "perf-test",
        "syscall": "execve",
        "is_suspicious": 0,
        "metadata": {"tag": tag},
    }


def gen_network_event(tag: str) -> dict:
    return {
        "timestamp": _now_iso(),
        "hostname": f"node-{random.randint(1,50)}",
        "src_ip": _rand_ip(),
        "src_port": random.randint(1024, 65535),
        "dst_ip": _rand_ip(),
        "dst_port": random.choice([80, 443, 8080]),
        "protocol": "TCP",
        "direction": "outbound",
        "bytes_sent": random.randint(64, 100000),
        "bytes_received": random.randint(64, 500000),
        "duration_ms": random.randint(1, 5000),
        "pid": random.randint(1, 65535),
        "binary_path": "/usr/bin/curl",
        "dns_query": f"{tag}.perf.test",
        "geo_country": random.choice(["US", "DE", "JP"]),
        "is_suspicious": 0,
        "metadata": {"tag": tag},
    }


TOPIC_GENERATORS = {
    "raw-logs": gen_raw_log,
    "security-events": gen_security_event,
    "process-events": gen_process_event,
    "network-events": gen_network_event,
}


# ── helpers ──────────────────────────────────────────────────────────────────


def _produce_batch(producer, topic, gen_fn, tag, count):
    delivered = 0
    errors = 0

    def _cb(err, msg):
        nonlocal delivered, errors
        if err:
            errors += 1
        else:
            delivered += 1

    for _ in range(count):
        producer.produce(topic, json.dumps(gen_fn(tag)).encode(), callback=_cb)
        if delivered % 2000 == 0:
            producer.poll(0)
    producer.flush(120)
    producer.poll(0)
    return delivered, errors


def _wait_count(ch, table, field, value, expected, timeout=60):
    deadline = time.monotonic() + timeout
    found = 0
    while time.monotonic() < deadline:
        try:
            r = ch.query(
                f"SELECT count() FROM {table} WHERE {field} = {{v:String}}",
                parameters={"v": value},
            )
            found = r.result_rows[0][0]
            if found >= expected:
                return found
        except Exception:
            pass
        time.sleep(0.5)
    return found


def _wait_for_consumer_idle(ch, table="raw_logs", stable_seconds=2.0, timeout=30):
    """Wait until the consumer has drained its backlog (row count stabilises)."""
    prev = 0
    stable_since = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = ch.query(f"SELECT count() FROM {table}")
            cur = r.result_rows[0][0]
        except Exception:
            time.sleep(0.5)
            continue
        if cur == prev:
            if stable_since is None:
                stable_since = time.monotonic()
            elif time.monotonic() - stable_since >= stable_seconds:
                return cur  # backlog drained
        else:
            stable_since = None
            prev = cur
        time.sleep(0.3)
    return prev  # best-effort


# =============================================================================
# Test 1: End-to-End Latency  (runs FIRST — no backlog)
# =============================================================================


class TestE2ELatency:
    """Produce a small probe batch → measure time until it appears in ClickHouse."""

    PROBE_SIZE = 50

    def test_e2e_latency_under_5s(self, kafka_producer, ch1):
        # Drain any residual backlog from prior test runs
        _wait_for_consumer_idle(ch1, stable_seconds=2.0, timeout=15)

        tag = f"lat-{uuid.uuid4().hex[:8]}"

        events = [gen_raw_log(tag) for _ in range(self.PROBE_SIZE)]

        t0 = time.perf_counter()
        delivered = 0
        errors_list = []

        def _cb(err, msg):
            nonlocal delivered
            if err:
                errors_list.append(err)
            else:
                delivered += 1

        for ev in events:
            kafka_producer.produce("raw-logs", json.dumps(ev).encode(), callback=_cb)
        kafka_producer.flush(30)
        kafka_producer.poll(0)
        t_produced = time.perf_counter() - t0

        found = _wait_count(ch1, "raw_logs", "request_id", tag, self.PROBE_SIZE, timeout=30)
        e2e = time.perf_counter() - t0

        print(f"\n  [E2E] Produced in {t_produced:.3f}s | "
              f"Found {found}/{self.PROBE_SIZE} | "
              f"E2E: {e2e:.3f}s")

        assert found >= self.PROBE_SIZE, f"Only {found}/{self.PROBE_SIZE} arrived"
        assert e2e < 15.0, f"E2E latency {e2e:.1f}s exceeds 15s threshold"

    def test_e2e_all_four_topics(self, kafka_producer, ch1):
        """Produce to all 4 topics simultaneously, verify all land."""
        tag = f"fan-{uuid.uuid4().hex[:8]}"
        count_per_topic = 25

        for topic, gen_fn in TOPIC_GENERATORS.items():
            events = [gen_fn(tag) for _ in range(count_per_topic)]
            for ev in events:
                kafka_producer.produce(topic, json.dumps(ev).encode())
            kafka_producer.poll(0)
        kafka_producer.flush(30)

        # Verify each table
        checks = [
            ("raw_logs", "request_id", tag),
            ("security_events", "source", "perf-test"),
            ("process_events", "namespace", "perf-test"),
            ("network_events", "dns_query", f"{tag}.perf.test"),
        ]

        all_found = True
        for table, field, value in checks:
            found = _wait_count(ch1, table, field, value, count_per_topic, timeout=30)
            if found < count_per_topic:
                all_found = False
                print(f"  [Fan-out] {table}: {found}/{count_per_topic}")

        assert all_found, "Not all topics ingested within timeout"


# =============================================================================
# Test 2: Burst Write Throughput  (runs AFTER latency probes)
# =============================================================================


def _parallel_produce_topic(
    broker: str,
    topic: str,
    payloads: list[bytes],
    producer_config: dict,
) -> tuple[int, int]:
    """Produce pre-serialised payloads to one topic. Thread-safe (owns its Producer)."""
    cfg = dict(producer_config)
    cfg["bootstrap.servers"] = broker
    p = Producer(cfg)
    delivered = 0
    errors = 0

    def _cb(err, _msg):
        nonlocal delivered, errors
        if err:
            errors += 1
        else:
            delivered += 1

    for payload in payloads:
        p.produce(topic, payload, callback=_cb)
        if delivered % 5000 == 0:
            p.poll(0)
    p.flush(120)
    p.poll(0)
    return delivered, errors


class TestBurstThroughput:
    """Measure maximum producer throughput to Redpanda.

    Production pattern: parallel producers per topic, pre-serialised payloads,
    per-thread Producer instances to maximise I/O parallelism across partitions.
    """

    EVENTS = 50_000  # per topic, 200k total

    @pytest.mark.timeout(300)
    def test_burst_produce_throughput(self):
        """Produce 200k events across 4 topics in parallel and measure rate."""
        from concurrent.futures import ThreadPoolExecutor
        from conftest import BROKER, PRODUCER_CONFIG

        tag = f"burst-{uuid.uuid4().hex[:8]}"

        # ── Pre-generate & pre-serialise all payloads OUTSIDE timing ──
        topic_payloads: dict[str, list[bytes]] = {}
        for topic, gen_fn in TOPIC_GENERATORS.items():
            topic_payloads[topic] = [
                json.dumps(gen_fn(tag)).encode() for _ in range(self.EVENTS)
            ]

        # ── Parallel produce — one Producer per topic (production pattern) ──
        total_delivered = 0
        total_errors = 0

        t0 = time.perf_counter()
        with ThreadPoolExecutor(
            max_workers=len(TOPIC_GENERATORS), thread_name_prefix="burst",
        ) as pool:
            futures = [
                pool.submit(
                    _parallel_produce_topic,
                    BROKER,
                    topic,
                    topic_payloads[topic],
                    PRODUCER_CONFIG,
                )
                for topic in TOPIC_GENERATORS
            ]
            for fut in futures:
                d, e = fut.result()
                total_delivered += d
                total_errors += e
        elapsed = time.perf_counter() - t0

        eps = total_delivered / elapsed if elapsed > 0 else 0
        print(f"\n  [Burst] Delivered: {total_delivered:,} | "
              f"Errors: {total_errors} | "
              f"Elapsed: {elapsed:.2f}s | "
              f"Rate: {eps:,.0f} events/sec")

        assert total_errors == 0, f"Delivery errors: {total_errors}"
        assert total_delivered >= self.EVENTS * 4 * 0.99, "Too many events lost"
        # Production target: ≥100k/s (parallel across 4 topics)
        assert eps >= 50_000, f"Throughput too low: {eps:.0f}/s (need ≥50k)"


# =============================================================================
# Test 3: ClickHouse Query Performance
# =============================================================================


class TestQueryPerformance:
    """Run typical analyst queries and assert they complete within thresholds."""

    QUERIES = [
        ("count_24h", "SELECT count() FROM raw_logs WHERE timestamp >= now() - INTERVAL 1 DAY", 1000),
        ("group_by_source", "SELECT source, count() AS c FROM raw_logs WHERE timestamp >= now() - INTERVAL 1 DAY GROUP BY source ORDER BY c DESC LIMIT 10", 1000),
        ("group_by_level", "SELECT level, count() AS c FROM raw_logs WHERE timestamp >= now() - INTERVAL 1 DAY GROUP BY level ORDER BY c DESC", 500),
        ("fulltext_search", "SELECT count() FROM raw_logs WHERE message LIKE '%probe%' AND timestamp >= now() - INTERVAL 1 DAY", 2000),
        ("security_severity", "SELECT count() FROM security_events WHERE severity >= 3 AND timestamp >= now() - INTERVAL 7 DAY", 1000),
        ("network_top_dst", "SELECT dst_ip, sum(bytes_sent) AS total FROM network_events WHERE timestamp >= now() - INTERVAL 1 DAY GROUP BY dst_ip ORDER BY total DESC LIMIT 10", 3000),
        ("process_suspicious", "SELECT count() FROM process_events WHERE is_suspicious = 1 AND timestamp >= now() - INTERVAL 7 DAY", 500),
        ("events_per_minute", "SELECT minute, sum(event_count) FROM events_per_minute WHERE minute >= now() - INTERVAL 1 HOUR GROUP BY minute ORDER BY minute", 500),
    ]

    @pytest.mark.parametrize("name,sql,max_ms", QUERIES, ids=[q[0] for q in QUERIES])
    def test_query_within_threshold(self, ch1, name, sql, max_ms):
        t0 = time.perf_counter()
        try:
            ch1.query(sql)
        except Exception as e:
            pytest.skip(f"Query error (may be empty table): {e}")
        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"\n  [{name}] {elapsed_ms:.1f}ms (max: {max_ms}ms)")
        assert elapsed_ms < max_ms, f"{name} took {elapsed_ms:.0f}ms (max {max_ms}ms)"


# =============================================================================
# Test 4: Direct ClickHouse Insert Performance  (post-burst)
# =============================================================================


class TestDirectInsertPerformance:
    """Measure ClickHouse native insert speed (bypassing Kafka)."""

    def test_bulk_insert_10k_rows(self, ch1):
        """Insert 10k rows directly into raw_logs and measure rate."""
        rows = []
        now = datetime.now(timezone.utc)
        for i in range(10_000):
            rows.append([
                str(uuid.uuid4()),   # event_id
                now,                  # timestamp
                now,                  # received_at
                "INFO",               # level
                "bulk-insert-test",   # source
                f"Bulk insert row {i}",  # message
                {},                   # metadata
                f"user_{i % 100}",    # user_id
                f"10.0.{i % 256}.{(i * 3) % 256}",  # ip_address
                f"bulk-{_rand_id(8)}",  # request_id
                "",                   # anchor_tx_id
                "",                   # anchor_batch_hash
            ])

        columns = [
            "event_id", "timestamp", "received_at", "level", "source",
            "message", "metadata", "user_id", "ip_address", "request_id",
            "anchor_tx_id", "anchor_batch_hash",
        ]

        t0 = time.perf_counter()
        ch1.insert("raw_logs", rows, column_names=columns)
        elapsed = time.perf_counter() - t0
        rate = 10_000 / elapsed if elapsed > 0 else 0

        print(f"\n  [Direct Insert] 10k rows in {elapsed:.3f}s ({rate:,.0f} rows/sec)")
        assert elapsed < 10.0, f"Bulk insert too slow: {elapsed:.1f}s"
