"""
CLIF Performance Test Suite
============================
Generates synthetic log events, publishes them to Redpanda, and measures:
  1. Producer throughput (events/sec to Redpanda)
  2. End-to-end latency (Redpanda → ClickHouse)
  3. ClickHouse query performance on recent data
  4. Sustained ingestion stability over configurable duration

Usage:
    pip install confluent-kafka clickhouse-connect rich
    python performance_test.py [--events 1000000] [--rate 100000] [--duration 600]
"""

from __future__ import annotations

import argparse
import json
import random
import string
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from confluent_kafka import Producer
import clickhouse_connect
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

# ── CLI ──────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="CLIF Storage Performance Tests")
parser.add_argument("--events", type=int, default=1_000_000, help="Total events to produce (default 1M)")
parser.add_argument("--rate", type=int, default=100_000, help="Target events/sec (default 100k)")
parser.add_argument("--duration", type=int, default=60, help="Sustained test duration in seconds (default 60)")
parser.add_argument("--kafka-broker", default="localhost:19092", help="Redpanda broker address")
parser.add_argument("--ch-host", default="localhost", help="ClickHouse host")
parser.add_argument("--ch-port", type=int, default=8123, help="ClickHouse HTTP port")
parser.add_argument("--ch-user", default="clif_admin")
parser.add_argument("--ch-password", default="Cl1f_Ch@ngeM3_2026!")
parser.add_argument("--ch-db", default="clif_logs")
args = parser.parse_args()

console = Console()

# ── Sample data generators ───────────────────────────────────────────────────

LEVELS = ["INFO", "INFO", "INFO", "WARN", "WARN", "ERROR", "CRITICAL"]
SOURCES = [
    "web-server", "api-gateway", "database", "auth-service",
    "firewall", "ids-sensor", "vpn-gateway", "dns-server",
    "mail-server", "proxy-server",
]
MESSAGES = [
    "Authentication failed for user {user}",
    "Successful login from {ip}",
    "Connection timeout to upstream {ip}:{port}",
    "SQL query executed in {ms}ms",
    "Rate limit exceeded for {ip}",
    "TLS handshake failed with {ip}",
    "File access denied: /etc/shadow by uid {uid}",
    "Outbound connection to {ip}:{port} blocked by policy",
    "Process {pid} spawned child {child_pid}",
    "DNS query for {domain} from {ip}",
    "Malware signature matched in file {path}",
    "Privilege escalation attempt detected for uid {uid}",
    "SSH brute-force attempt from {ip}",
    "Certificate expired for {domain}",
    "Unusual data transfer: {bytes} bytes to {ip}",
]
DOMAINS = ["evil.com", "c2.badactor.net", "update.legit.org", "api.internal.corp", "cdn.example.com"]


def _random_ip() -> str:
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _random_id() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def generate_raw_log(ts: datetime | None = None) -> dict:
    """Generate a single realistic raw log event."""
    if ts is None:
        ts = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 86400))
    ip = _random_ip()
    msg_template = random.choice(MESSAGES)
    msg = msg_template.format(
        user=f"user_{random.randint(1000,9999)}",
        ip=ip,
        port=random.choice([22, 80, 443, 3306, 5432, 8080, 8443]),
        ms=random.randint(1, 5000),
        uid=random.randint(0, 65534),
        pid=random.randint(1, 65535),
        child_pid=random.randint(1, 65535),
        domain=random.choice(DOMAINS),
        path=f"/usr/bin/{_random_id()}",
        bytes=random.randint(1024, 10_000_000),
    )
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "level": random.choice(LEVELS),
        "source": random.choice(SOURCES),
        "message": msg,
        "metadata": {
            "user_id": f"user_{random.randint(1000, 9999)}",
            "ip_address": ip,
            "request_id": str(uuid.uuid4())[:8],
        },
    }


def generate_security_event(ts: datetime | None = None) -> dict:
    if ts is None:
        ts = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 86400))
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "severity": random.choice([0, 0, 1, 1, 2, 3, 4]),
        "category": random.choice(["auth", "malware", "exfiltration", "brute-force", "privilege-escalation"]),
        "source": random.choice(SOURCES),
        "description": random.choice(MESSAGES).format(
            user="user_" + str(random.randint(1000, 9999)), ip=_random_ip(),
            port=443, ms=100, uid=0, pid=1, child_pid=2,
            domain="evil.com", path="/bin/sh", bytes=999999,
        ),
        "user_id": f"user_{random.randint(1000, 9999)}",
        "ip_address": _random_ip(),
        "hostname": f"node-{random.randint(1,50)}",
        "mitre_tactic": random.choice(["initial-access", "execution", "persistence", "privilege-escalation", "lateral-movement"]),
        "mitre_technique": f"T{random.randint(1000, 1999)}",
        "ai_confidence": round(random.uniform(0.1, 0.99), 2),
        "metadata": {},
    }


def generate_process_event(ts: datetime | None = None) -> dict:
    if ts is None:
        ts = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 86400))
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "hostname": f"node-{random.randint(1,50)}",
        "pid": random.randint(1, 65535),
        "ppid": random.randint(1, 65535),
        "uid": random.randint(0, 65534),
        "gid": random.randint(0, 65534),
        "binary_path": random.choice(["/bin/bash", "/usr/bin/python3", "/usr/sbin/sshd", "/bin/cat", "/usr/bin/curl"]),
        "arguments": f"--flag {_random_id()}",
        "cwd": "/home/user",
        "exit_code": random.choice([0, 0, 0, 1, 127, 137]),
        "container_id": _random_id() + _random_id(),
        "pod_name": f"app-{_random_id()}",
        "namespace": random.choice(["default", "production", "staging", "monitoring"]),
        "syscall": random.choice(["execve", "fork", "clone", "connect", "open", "read", "write"]),
        "is_suspicious": random.choice([0, 0, 0, 0, 1]),
        "metadata": {},
    }


def generate_network_event(ts: datetime | None = None) -> dict:
    if ts is None:
        ts = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 86400))
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "hostname": f"node-{random.randint(1,50)}",
        "src_ip": _random_ip(),
        "src_port": random.randint(1024, 65535),
        "dst_ip": _random_ip(),
        "dst_port": random.choice([22, 80, 443, 3306, 5432, 8080, 8443, 53]),
        "protocol": random.choice(["TCP", "TCP", "TCP", "UDP", "UDP"]),
        "direction": random.choice(["inbound", "outbound", "outbound", "outbound"]),
        "bytes_sent": random.randint(64, 1_000_000),
        "bytes_received": random.randint(64, 5_000_000),
        "duration_ms": random.randint(1, 30000),
        "pid": random.randint(1, 65535),
        "binary_path": random.choice(["/usr/bin/curl", "/usr/bin/wget", "/usr/sbin/nginx", "/usr/bin/ssh"]),
        "dns_query": random.choice(DOMAINS + [""]),
        "geo_country": random.choice(["US", "CN", "RU", "DE", "GB", "JP", ""]),
        "is_suspicious": random.choice([0, 0, 0, 0, 1]),
        "metadata": {},
    }


TOPIC_GENERATORS = {
    "raw-logs": generate_raw_log,
    "security-events": generate_security_event,
    "process-events": generate_process_event,
    "network-events": generate_network_event,
}

# ── Kafka producer ───────────────────────────────────────────────────────────

_delivery_count = 0
_delivery_errors = 0


def _delivery_cb(err, msg):
    global _delivery_count, _delivery_errors
    if err:
        _delivery_errors += 1
    else:
        _delivery_count += 1


def create_producer() -> Producer:
    return Producer({
        "bootstrap.servers": args.kafka_broker,
        "linger.ms": 5,
        "batch.num.messages": 10000,
        "queue.buffering.max.messages": 2_000_000,
        "queue.buffering.max.kbytes": 2_097_152,
        "compression.type": "zstd",
        "acks": "all",
        "enable.idempotence": True,
        "message.max.bytes": 10_485_760,
    })


# ── ClickHouse client ───────────────────────────────────────────────────────


def get_ch_client():
    return clickhouse_connect.get_client(
        host=args.ch_host,
        port=args.ch_port,
        username=args.ch_user,
        password=args.ch_password,
        database=args.ch_db,
    )


# ── Test 1: Burst produce ───────────────────────────────────────────────────


def test_burst_produce():
    """Produce --events events as fast as possible and measure throughput."""
    global _delivery_count, _delivery_errors
    _delivery_count = 0
    _delivery_errors = 0

    console.rule("[bold cyan]Test 1: Burst Produce to Redpanda")
    producer = create_producer()
    topics = list(TOPIC_GENERATORS.keys())
    n = args.events

    console.print(f"  Producing {n:,} events across {len(topics)} topics …")
    t0 = time.perf_counter()

    with Progress(
        SpinnerColumn(), BarColumn(), TextColumn("{task.completed:,}/{task.total:,}"),
        console=console,
    ) as progress:
        task = progress.add_task("Producing", total=n)
        for i in range(n):
            topic = topics[i % len(topics)]
            event = TOPIC_GENERATORS[topic]()
            producer.produce(topic, json.dumps(event).encode(), callback=_delivery_cb)
            if i % 10000 == 0:
                producer.poll(0)
                progress.update(task, completed=i)
        producer.flush(timeout=120)
        progress.update(task, completed=n)

    elapsed = time.perf_counter() - t0
    eps = n / elapsed if elapsed > 0 else 0

    console.print(f"\n  [green]✔[/green]  Produced  : {_delivery_count:,} events")
    console.print(f"  [green]✔[/green]  Errors    : {_delivery_errors:,}")
    console.print(f"  [green]✔[/green]  Elapsed   : {elapsed:.2f}s")
    console.print(f"  [green]✔[/green]  Throughput: {eps:,.0f} events/sec")

    return {"produced": _delivery_count, "errors": _delivery_errors, "elapsed_s": elapsed, "eps": eps}


# ── Test 2: End-to-end latency ───────────────────────────────────────────────


def test_e2e_latency():
    """Produce a small tagged batch and measure how fast it appears in ClickHouse."""
    console.rule("[bold cyan]Test 2: End-to-End Latency (Redpanda → ClickHouse)")
    tag = f"perf-test-{uuid.uuid4().hex[:8]}"
    n_probe = 100

    producer = create_producer()
    ch = get_ch_client()

    console.print(f"  Producing {n_probe} tagged events (tag={tag}) …")
    t0 = time.perf_counter()
    for _ in range(n_probe):
        event = generate_raw_log()
        event["metadata"]["request_id"] = tag
        producer.produce("raw-logs", json.dumps(event).encode(), callback=_delivery_cb)
    producer.flush(timeout=30)
    t_produced = time.perf_counter() - t0
    console.print(f"  Produced in {t_produced:.3f}s — waiting for ClickHouse …")

    # Poll ClickHouse until all events arrive
    deadline = time.perf_counter() + 60  # 60s timeout
    found = 0
    while time.perf_counter() < deadline:
        try:
            result = ch.query(
                "SELECT count() FROM raw_logs WHERE request_id = {tag:String}",
                parameters={"tag": tag},
            )
            found = result.result_rows[0][0]
            if found >= n_probe:
                break
        except Exception:
            pass
        time.sleep(0.2)

    e2e = time.perf_counter() - t0

    if found >= n_probe:
        console.print(f"  [green]✔[/green]  All {found} events landed in ClickHouse")
        console.print(f"  [green]✔[/green]  End-to-end latency: {e2e:.3f}s  ({e2e/n_probe*1000:.1f}ms per event)")
    else:
        console.print(f"  [red]✘[/red]  Only {found}/{n_probe} events found after 60s timeout")

    return {"tag": tag, "expected": n_probe, "found": found, "e2e_seconds": e2e}


# ── Test 3: Query performance ────────────────────────────────────────────────


def test_query_performance():
    """Run a set of typical analyst queries and measure response times."""
    console.rule("[bold cyan]Test 3: ClickHouse Query Performance")
    ch = get_ch_client()

    queries = [
        ("Count last 24h", "SELECT count() FROM raw_logs WHERE timestamp >= now() - INTERVAL 1 DAY"),
        ("Count by source (24h)", "SELECT source, count() AS c FROM raw_logs WHERE timestamp >= now() - INTERVAL 1 DAY GROUP BY source ORDER BY c DESC LIMIT 10"),
        ("Count by level (24h)", "SELECT level, count() AS c FROM raw_logs WHERE timestamp >= now() - INTERVAL 1 DAY GROUP BY level ORDER BY c DESC"),
        ("Full-text search", "SELECT count() FROM raw_logs WHERE message LIKE '%Authentication failed%' AND timestamp >= now() - INTERVAL 1 DAY"),
        ("Security events severity≥3", "SELECT count() FROM security_events WHERE severity >= 3 AND timestamp >= now() - INTERVAL 7 DAY"),
        ("Network top destinations", "SELECT dst_ip, sum(bytes_sent) AS total FROM network_events WHERE timestamp >= now() - INTERVAL 1 DAY GROUP BY dst_ip ORDER BY total DESC LIMIT 10"),
        ("Events per minute (1h)", "SELECT minute, sum(event_count) FROM events_per_minute WHERE minute >= now() - INTERVAL 1 HOUR GROUP BY minute ORDER BY minute"),
        ("Process suspicious", "SELECT count() FROM process_events WHERE is_suspicious = 1 AND timestamp >= now() - INTERVAL 7 DAY"),
    ]

    table = Table(title="Query Performance")
    table.add_column("Query", style="cyan", min_width=30)
    table.add_column("Time (ms)", justify="right", style="green")
    table.add_column("Rows", justify="right")

    results = []
    for label, sql in queries:
        try:
            t0 = time.perf_counter()
            result = ch.query(sql)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            row_count = len(result.result_rows)
            table.add_row(label, f"{elapsed_ms:.1f}", str(row_count))
            results.append({"query": label, "ms": elapsed_ms, "rows": row_count})
        except Exception as exc:
            table.add_row(label, "ERROR", str(exc))
            results.append({"query": label, "ms": -1, "error": str(exc)})

    console.print(table)
    return results


# ── Test 4: Sustained ingestion ──────────────────────────────────────────────


def test_sustained_ingestion():
    """Produce at target rate for --duration seconds and monitor stability."""
    console.rule(f"[bold cyan]Test 4: Sustained Ingestion ({args.duration}s at {args.rate:,}/s)")
    global _delivery_count, _delivery_errors
    _delivery_count = 0
    _delivery_errors = 0

    producer = create_producer()
    topics = list(TOPIC_GENERATORS.keys())
    target_rate = args.rate
    duration = args.duration
    interval = 1.0 / target_rate if target_rate > 0 else 0

    console.print(f"  Target: {target_rate:,} events/sec for {duration}s = {target_rate * duration:,} total")

    samples: list[dict] = []
    t_start = time.perf_counter()
    t_end = t_start + duration
    produced_this_sec = 0
    sec_start = t_start

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TextColumn("{task.completed}s / {task.total}s"),
        console=console,
    ) as progress:
        task = progress.add_task("Sustained", total=duration)

        while time.perf_counter() < t_end:
            topic = random.choice(topics)
            event = TOPIC_GENERATORS[topic]()
            producer.produce(topic, json.dumps(event).encode(), callback=_delivery_cb)
            produced_this_sec += 1

            if produced_this_sec % 1000 == 0:
                producer.poll(0)

            now = time.perf_counter()
            elapsed_in_sec = now - sec_start
            if elapsed_in_sec >= 1.0:
                actual_rate = produced_this_sec / elapsed_in_sec
                samples.append({"second": int(now - t_start), "rate": actual_rate})
                progress.update(task, completed=int(now - t_start))
                produced_this_sec = 0
                sec_start = now

                # Basic rate limiting — sleep if we're ahead
                if actual_rate > target_rate * 1.1:
                    time.sleep(0.001)

        producer.flush(timeout=120)
        progress.update(task, completed=duration)

    total_elapsed = time.perf_counter() - t_start
    avg_rate = _delivery_count / total_elapsed if total_elapsed > 0 else 0

    console.print(f"\n  [green]✔[/green]  Delivered : {_delivery_count:,}")
    console.print(f"  [green]✔[/green]  Errors    : {_delivery_errors:,}")
    console.print(f"  [green]✔[/green]  Duration  : {total_elapsed:.1f}s")
    console.print(f"  [green]✔[/green]  Avg rate  : {avg_rate:,.0f} events/sec")

    if samples:
        rates = [s["rate"] for s in samples]
        console.print(f"  [green]✔[/green]  Min rate  : {min(rates):,.0f}/s")
        console.print(f"  [green]✔[/green]  Max rate  : {max(rates):,.0f}/s")

    return {
        "delivered": _delivery_count,
        "errors": _delivery_errors,
        "duration_s": total_elapsed,
        "avg_rate": avg_rate,
    }


# ── Main ─────────────────────────────────────────────────────────────────────


def main():
    console.print("\n[bold magenta]═══  CLIF Storage Infrastructure — Performance Test Suite  ═══[/bold magenta]\n")
    console.print(f"  Redpanda : {args.kafka_broker}")
    console.print(f"  ClickHouse: {args.ch_host}:{args.ch_port}")
    console.print()

    results = {}

    # Run tests in order
    results["burst_produce"] = test_burst_produce()
    results["e2e_latency"] = test_e2e_latency()
    results["query_performance"] = test_query_performance()
    results["sustained"] = test_sustained_ingestion()

    # ── Summary ──────────────────────────────────────────────────────────
    console.rule("[bold green]Summary")
    summary = Table(title="Performance Summary")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", justify="right", style="green")
    summary.add_column("Target", justify="right", style="yellow")
    summary.add_column("Status", justify="center")

    burst_eps = results["burst_produce"]["eps"]
    summary.add_row("Burst throughput", f"{burst_eps:,.0f}/s", "100,000/s",
                     "✅" if burst_eps >= 100_000 else "⚠️")

    e2e = results["e2e_latency"]["e2e_seconds"]
    summary.add_row("E2E latency", f"{e2e:.2f}s", "<1.0s",
                     "✅" if e2e < 1.0 else "⚠️")

    e2e_found = results["e2e_latency"]["found"]
    e2e_expected = results["e2e_latency"]["expected"]
    summary.add_row("E2E completeness", f"{e2e_found}/{e2e_expected}", "100%",
                     "✅" if e2e_found >= e2e_expected else "❌")

    # Fastest query
    query_times = [q["ms"] for q in results["query_performance"] if q.get("ms", -1) > 0]
    if query_times:
        max_q = max(query_times)
        summary.add_row("Slowest query", f"{max_q:.0f}ms", "<500ms",
                         "✅" if max_q < 500 else "⚠️")

    sust = results["sustained"]["avg_rate"]
    summary.add_row("Sustained rate", f"{sust:,.0f}/s", f"{args.rate:,}/s",
                     "✅" if sust >= args.rate * 0.9 else "⚠️")

    zero_loss = results["burst_produce"]["errors"] == 0 and results["sustained"]["errors"] == 0
    summary.add_row("Zero message loss", "Yes" if zero_loss else "No", "Yes",
                     "✅" if zero_loss else "❌")

    console.print(summary)
    console.print()

    # Exit code
    all_pass = (
        burst_eps >= 50_000  # relaxed for dev environments
        and e2e < 5.0
        and e2e_found >= e2e_expected
    )
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
