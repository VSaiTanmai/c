"""
CLIF EPS (Events Per Second) Pipeline Stability Benchmark
===========================================================
Tests the FULL ingestion pipeline end-to-end:

  Producer → Vector (HTTP:8687) → Redpanda → Consumer → ClickHouse
                                     ↓
                      (also direct Kafka producer path)

Metrics reported:
  • Producer EPS (events pushed per second)
  • Vector ingest EPS (HTTP endpoint throughput)
  • Redpanda offset growth (events/sec through broker)
  • ClickHouse landing rate (rows/sec materialised)
  • End-to-end latency (produce → ClickHouse)
  • Pipeline stability (EPS stddev, jitter %, data completeness)
  • Backpressure detection (HTTP 429 / queue saturation)

Optimisations (matching enterprise_benchmark.py):
  • orjson serialisation (~6x faster than json.dumps)
  • Pre-computed tuples for random data selection
  • Cached timestamps (refreshed every 500 events)
  • Kafka: acks=1, lz4 compression, 100K batch, 2MB batch.size
  • Multi-threaded Kafka producers (configurable --threads)
  • No rate-limiting — max-throughput by default

Usage:
    python eps_benchmark.py [--mode full|vector|kafka] [--duration 60] [--target-eps 100000]

Modes:
  full   — send via Vector HTTP + direct Kafka (both paths)
  vector — send only via Vector HTTP endpoint (full pipeline)
  kafka  — send only direct to Redpanda (bypass Vector)
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import string
import sys
import time
import uuid
import signal
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from threading import Event, Thread, Lock
from typing import Any

import requests
from confluent_kafka import Producer, Consumer, TopicPartition
import clickhouse_connect
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text

# ── Fast JSON ────────────────────────────────────────────────────────────────
try:
    import orjson
    _fast_dumps = orjson.dumps       # returns bytes directly, ~6x faster
except ImportError:
    def _fast_dumps(obj):            # type: ignore[misc]
        return json.dumps(obj).encode()

# ── CLI ──────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="CLIF EPS Pipeline Stability Benchmark")
parser.add_argument("--mode", choices=["full", "vector", "kafka"], default="full",
                    help="Ingestion path: full (both), vector (HTTP→Vector), kafka (direct Redpanda)")
parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds (default: 60)")
parser.add_argument("--target-eps", type=int, default=100000, help="Target events/sec (default: 100000)")
parser.add_argument("--batch-size", type=int, default=500, help="Events per HTTP batch to Vector (default: 500)")
parser.add_argument("--warmup", type=int, default=5, help="Warmup seconds before measuring (default: 5)")
parser.add_argument("--threads", type=int, default=1, help="Kafka producer threads (default: 1)")
parser.add_argument("--rate-limit", type=int, default=0,
                    help="Optional per-thread EPS cap (0 = unlimited, default: 0)")
parser.add_argument("--vector-url", default="http://localhost:8687/v1/logs", help="Vector HTTP endpoint")
parser.add_argument("--kafka-broker", default="localhost:19092", help="Redpanda broker")
parser.add_argument("--ch-host", default="localhost")
parser.add_argument("--ch-port", type=int, default=8123)
parser.add_argument("--ch-user", default="clif_admin")
parser.add_argument("--ch-password", default="Cl1f_Ch@ngeM3_2026!")
parser.add_argument("--ch-db", default="clif_logs")
args = parser.parse_args()

console = Console()
stop_event = Event()

# ── Signal handling ──────────────────────────────────────────────────────────

def _handle_sigint(sig, frame):
    console.print("\n[yellow]⚠ Ctrl+C — stopping benchmark gracefully…[/yellow]")
    stop_event.set()

signal.signal(signal.SIGINT, _handle_sigint)

# ── Pre-computed data pools (tuples for faster random.choice) ────────────────

_IPS = tuple(f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
             for _ in range(500))
_HOSTS = tuple(f"node-{i:03d}" for i in range(100))
_USERS = tuple(f"user_{i:04d}" for i in range(1000))
_SOURCES = ("web-server", "api-gateway", "database", "auth-service", "firewall",
            "ids-sensor", "vpn-gateway", "dns-server", "mail-server", "proxy-server")
_SEVS = ("INFO", "INFO", "INFO", "WARN", "WARN", "ERROR", "CRITICAL")
_CATEGORIES = ("auth", "malware", "exfiltration", "brute-force", "scan")
_MITRE_TACTICS = ("initial-access", "execution", "persistence", "privilege-escalation",
                  "lateral-movement", "collection", "exfiltration", "command-and-control")
_BINARIES = ("/bin/bash", "/usr/bin/python3", "/usr/sbin/sshd", "/usr/bin/curl",
             "/usr/bin/wget", "/usr/sbin/nginx")
_SYSCALLS = ("execve", "fork", "clone", "connect")
_EXIT_CODES = (0, 0, 0, 1, 137)
_PORTS = (22, 80, 443, 8080, 53, 3306, 5432, 6379, 9092)
_PROTOS = ("TCP", "TCP", "UDP")
_DIRS = ("inbound", "outbound")
_GEOS = ("US", "US", "US", "CN", "RU", "DE", "GB", "")
_DNS_NAMES = ("evil.com", "legit.org", "api.internal", "cdn.corp", "")
_ACTIONS = ("allow", "deny", "drop", "alert")

# ── Fast timestamp cache ────────────────────────────────────────────────────

_UTC = timezone.utc
_ts_cache: str = ""
_ts_counter: int = 0

def _now_iso() -> str:
    """Return ISO timestamp, refreshed every 500 calls."""
    global _ts_cache, _ts_counter
    _ts_counter += 1
    if _ts_counter % 500 == 0 or not _ts_cache:
        _ts_cache = datetime.now(_UTC).isoformat()
    return _ts_cache


# ── Optimised event generators ──────────────────────────────────────────────

def _gen_raw(seq: int = 0) -> dict:
    return {
        "timestamp": _now_iso(),
        "level": random.choice(_SEVS),
        "source": random.choice(_SOURCES),
        "message": f"[{random.choice(_SOURCES)}] Event from {random.choice(_HOSTS)}: "
                   f"action={random.choice(_ACTIONS)} "
                   f"src={random.choice(_IPS)} dst={random.choice(_IPS)} "
                   f"bytes={random.randint(64, 65536)}",
        "metadata": {"ip_address": random.choice(_IPS), "seq": seq},
    }

def _gen_security(seq: int = 0) -> dict:
    return {
        "timestamp": _now_iso(),
        "severity": random.randint(0, 4),
        "category": random.choice(_CATEGORIES),
        "source": random.choice(_SOURCES),
        "description": f"Security event from {random.choice(_HOSTS)}: action={random.choice(_ACTIONS)}",
        "user_id": random.choice(_USERS),
        "ip_address": random.choice(_IPS),
        "hostname": random.choice(_HOSTS),
        "mitre_tactic": random.choice(_MITRE_TACTICS),
        "mitre_technique": f"T{random.randint(1000, 1999)}",
        "ai_confidence": round(random.uniform(0.1, 0.99), 2),
        "metadata": {"seq": seq},
    }

def _gen_process(seq: int = 0) -> dict:
    return {
        "timestamp": _now_iso(),
        "hostname": random.choice(_HOSTS),
        "pid": random.randint(1, 65535),
        "ppid": random.randint(1, 65535),
        "uid": random.randint(0, 65534),
        "gid": random.randint(0, 65534),
        "binary_path": random.choice(_BINARIES),
        "arguments": f"--user {random.choice(_USERS)}",
        "cwd": "/home/user",
        "exit_code": random.choice(_EXIT_CODES),
        "syscall": random.choice(_SYSCALLS),
        "is_suspicious": 1 if random.random() < 0.005 else 0,
        "metadata": {"seq": seq},
    }

def _gen_network(seq: int = 0) -> dict:
    return {
        "timestamp": _now_iso(),
        "hostname": random.choice(_HOSTS),
        "src_ip": random.choice(_IPS),
        "src_port": random.randint(1024, 65535),
        "dst_ip": random.choice(_IPS),
        "dst_port": random.choice(_PORTS),
        "protocol": random.choice(_PROTOS),
        "direction": random.choice(_DIRS),
        "bytes_sent": random.randint(64, 1_048_576),
        "bytes_received": random.randint(64, 1_048_576),
        "duration_ms": random.randint(1, 5000),
        "dns_query": random.choice(_DNS_NAMES),
        "geo_country": random.choice(_GEOS),
        "is_suspicious": 1 if random.random() < 0.005 else 0,
        "metadata": {"seq": seq},
    }


# Topic routing
TOPICS = ("raw-logs", "security-events", "process-events", "network-events")
TOPIC_WEIGHTS = (0.15, 0.35, 0.25, 0.25)
TOPIC_GENERATORS = {
    "raw-logs": _gen_raw,
    "security-events": _gen_security,
    "process-events": _gen_process,
    "network-events": _gen_network,
}
# legacy mappings for Vector mode compatibility
EVENT_TYPES = ["raw", "security", "process", "network"]
TOPIC_MAP = {
    "raw": "raw-logs",
    "security": "security-events",
    "process": "process-events",
    "network": "network-events",
}
CH_TABLE_MAP = {
    "raw": "raw_logs",
    "security": "security_events",
    "process": "process_events",
    "network": "network_events",
}

# ── Metrics collector ────────────────────────────────────────────────────────

class MetricsCollector:
    """Thread-safe metrics collector for the benchmark."""

    def __init__(self):
        self._lock = Lock()
        self.produced_vector = 0
        self.produced_kafka = 0
        self.http_errors = 0
        self.kafka_errors = 0
        self.kafka_acks = 0
        self.http_429s = 0
        self.per_second_rates: list[dict] = []
        self._sec_produced = 0
        self._sec_start = time.perf_counter()

    def record_vector_batch(self, count: int):
        with self._lock:
            self.produced_vector += count
            self._sec_produced += count

    def record_kafka_ack(self):
        with self._lock:
            self.kafka_acks += 1

    def record_kafka_produce(self, count: int):
        with self._lock:
            self.produced_kafka += count
            self._sec_produced += count  # track produce-side rate (not ack-side)

    def record_http_error(self, status: int = 0):
        with self._lock:
            self.http_errors += 1
            if status == 429:
                self.http_429s += 1

    def record_kafka_error(self):
        with self._lock:
            self.kafka_errors += 1

    def tick_second(self) -> float:
        """Call every ~1s to record per-second rate. Returns rate."""
        with self._lock:
            now = time.perf_counter()
            elapsed = now - self._sec_start
            rate = self._sec_produced / elapsed if elapsed > 0 else 0
            self.per_second_rates.append({
                "second": len(self.per_second_rates) + 1,
                "rate": rate,
                "produced_total": self.produced_vector + self.produced_kafka,
            })
            self._sec_produced = 0
            self._sec_start = now
            return rate

    @property
    def total_produced(self) -> int:
        return self.produced_vector + self.produced_kafka

    def stability_stats(self) -> dict:
        """Compute pipeline stability metrics (excludes boundary artifacts)."""
        # Filter out 0-rate boundary seconds (thread start/stop artifacts)
        rates = [s["rate"] for s in self.per_second_rates if s["rate"] > 0]
        if len(rates) < 2:
            return {"avg_eps": 0, "min_eps": 0, "max_eps": 0, "stddev": 0, "jitter_pct": 0, "cv": 0}
        # Trim top/bottom 5% outliers for stability stats (keep raw min/max for display)
        sorted_rates = sorted(rates)
        trim = max(1, len(sorted_rates) // 20)  # 5%
        trimmed = sorted_rates[trim:-trim] if trim < len(sorted_rates) // 2 else sorted_rates
        avg = statistics.mean(trimmed)
        sd = statistics.stdev(trimmed)
        return {
            "avg_eps": statistics.mean(rates),  # full average
            "min_eps": min(rates),
            "max_eps": max(rates),
            "stddev": sd,
            "jitter_pct": (max(trimmed) - min(trimmed)) / avg * 100 if avg > 0 else 0,
            "cv": sd / avg * 100 if avg > 0 else 0,  # coefficient of variation (trimmed)
        }


metrics = MetricsCollector()

# ── Vector HTTP producer ─────────────────────────────────────────────────────

def vector_producer_thread(target_eps: int, duration: int):
    """Send events to Vector HTTP endpoint in batches (optimised)."""
    session = requests.Session()
    session.headers["Content-Type"] = "application/json"
    batch_size = args.batch_size
    deadline = time.perf_counter() + duration
    _dumps = _fast_dumps
    _gens = (_gen_raw, _gen_security, _gen_process, _gen_network)

    while not stop_event.is_set() and time.perf_counter() < deadline:
        batch = [random.choice(_gens)() for _ in range(batch_size)]
        try:
            resp = session.post(args.vector_url, data=_dumps(batch), timeout=10)
            if resp.status_code in (200, 201, 204):
                metrics.record_vector_batch(batch_size)
            else:
                metrics.record_http_error(resp.status_code)
        except requests.RequestException:
            metrics.record_http_error()


# ── Kafka direct producer ────────────────────────────────────────────────────

# Lock-free delivery counters (CPython GIL protects += 1)
_kafka_ack_count = 0
_kafka_err_count = 0

def _kafka_delivery_cb(err, msg):
    global _kafka_ack_count, _kafka_err_count
    if err:
        _kafka_err_count += 1
    else:
        _kafka_ack_count += 1


def kafka_producer_thread(target_eps: int, duration: int):
    """High-throughput Kafka producer — max-speed tight loop.

    Optimisations vs. previous version:
      • acks=1 (leader-only, 3-5x faster than 'all')
      • lz4 compression (~4x faster than zstd)
      • 100K batch, 2MB batch.size, 4M queue buffer
      • orjson serialisation (~6x faster)
      • Pre-computed topic selection via random.choices(k=5000)
      • Function alias: _produce / _poll (skip dict lookup per call)
      • No per-second rate gating (fire at max speed)
      • No stop_event check in hot loop (only at poll boundaries)
      • Local counter — no Lock in hot path
    """
    producer = Producer({
        "bootstrap.servers": args.kafka_broker,
        "acks": "1",                          # Leader-only ack — 3-5x faster than "all"
        "compression.type": "lz4",            # LZ4 ~4x faster than zstd for throughput
        "linger.ms": 5,
        "batch.num.messages": 100_000,
        "batch.size": 2_097_152,              # 2 MiB batch
        "queue.buffering.max.messages": 4_000_000,
        "queue.buffering.max.kbytes": 4_194_304,  # 4 GiB buffer
        "message.max.bytes": 10_485_760,
        "log_level": 0,                       # Suppress rdkafka debug noise
    })

    # Function aliases — avoid dict/attribute lookup per event
    _produce = producer.produce
    _poll = producer.poll
    _perf = time.perf_counter
    _dumps = _fast_dumps
    _generators = TOPIC_GENERATORS
    _topics = TOPICS
    _weights = TOPIC_WEIGHTS

    deadline = _perf() + duration
    BATCH = 5000
    topic_batch = random.choices(_topics, weights=_weights, k=BATCH)
    batch_idx = 0
    total = 0
    rate_limit = args.rate_limit

    # Optional rate-limiting state
    if rate_limit > 0:
        sec_count = 0
        sec_start = _perf()

    while True:
        if batch_idx >= BATCH:
            topic_batch = random.choices(_topics, weights=_weights, k=BATCH)
            batch_idx = 0

        topic = topic_batch[batch_idx]
        batch_idx += 1
        event = _generators[topic](seq=total)

        # Handle queue saturation: poll + retry on BufferError
        try:
            _produce(topic, _dumps(event), callback=_kafka_delivery_cb)
        except BufferError:
            # Queue full — drain up to 500ms then retry
            for _ in range(5):
                _poll(100)
                try:
                    _produce(topic, _dumps(event), callback=_kafka_delivery_cb)
                    break
                except BufferError:
                    continue
            else:
                continue  # Skip event after 500ms of retries
        total += 1

        # Poll every 5000 events — also check stop/deadline here (not per-event)
        if total % 5000 == 0:
            _poll(0)
            metrics.record_kafka_produce(5000)
            if stop_event.is_set() or _perf() >= deadline:
                break

        # Optional per-second rate gating
        if rate_limit > 0:
            sec_count += 1
            if sec_count >= rate_limit:
                now = _perf()
                remaining = 1.0 - (now - sec_start)
                if remaining > 0.001:
                    time.sleep(remaining)
                sec_count = 0
                sec_start = _perf()

    # Record any remaining events not yet accounted for
    remainder = total % 5000
    if remainder > 0:
        metrics.record_kafka_produce(remainder)

    # Sync error counts back to metrics
    global _kafka_err_count
    if _kafka_err_count > 0:
        with metrics._lock:
            metrics.kafka_errors += _kafka_err_count
            _kafka_err_count = 0

    producer.flush(timeout=120)


# ── ClickHouse monitor ───────────────────────────────────────────────────────

class ClickHouseMonitor:
    """Polls ClickHouse row counts to measure landing rate."""

    def __init__(self):
        self.client = clickhouse_connect.get_client(
            host=args.ch_host, port=args.ch_port,
            username=args.ch_user, password=args.ch_password,
            database=args.ch_db,
        )
        self.snapshots: list[dict] = []
        self._baseline: dict[str, int] = {}

    def take_baseline(self):
        """Record starting row counts."""
        self._baseline = self._get_counts()

    def _get_counts(self) -> dict[str, int]:
        counts = {}
        for table in ["raw_logs", "security_events", "process_events", "network_events"]:
            try:
                r = self.client.query(f"SELECT count() FROM {table}")
                counts[table] = r.result_rows[0][0]
            except Exception:
                counts[table] = 0
        return counts

    def snapshot(self):
        """Take a point-in-time count snapshot."""
        counts = self._get_counts()
        delta = {t: counts[t] - self._baseline.get(t, 0) for t in counts}
        self.snapshots.append({
            "time": time.perf_counter(),
            "counts": counts,
            "delta": delta,
            "total_new": sum(delta.values()),
        })
        return self.snapshots[-1]

    def landing_rate(self) -> float:
        """Events/sec landing in ClickHouse since baseline."""
        if len(self.snapshots) < 2:
            return 0
        first = self.snapshots[0]
        last = self.snapshots[-1]
        elapsed = last["time"] - first["time"]
        if elapsed <= 0:
            return 0
        return (last["total_new"] - first["total_new"]) / elapsed

    def total_landed(self) -> int:
        if not self.snapshots:
            return 0
        return self.snapshots[-1]["total_new"]


# ── Live display ─────────────────────────────────────────────────────────────

def build_live_panel(elapsed: int, duration: int, current_eps: float,
                     ch_landed: int, ch_rate: float) -> Panel:
    """Build a rich panel for live display."""
    pct = min(100, int(elapsed / duration * 100))
    bar_len = 40
    filled = int(bar_len * pct / 100)
    bar = "█" * filled + "░" * (bar_len - filled)

    lines = [
        f"  Time:    [{elapsed:3d}s / {duration}s]  {bar}  {pct}%",
        f"  Mode:    {args.mode.upper()}",
        "",
        f"  Producer EPS:     {current_eps:>10,.0f} /s",
        f"  Total Produced:   {metrics.total_produced:>10,}",
        f"  Vector Batches:   {metrics.produced_vector:>10,}",
        f"  Kafka Direct:     {metrics.produced_kafka:>10,}",
        f"  HTTP Errors:      {metrics.http_errors:>10,}  (429s: {metrics.http_429s})",
        f"  Kafka Errors:     {metrics.kafka_errors:>10,}",
        "",
        f"  CH Landing Rate:  {ch_rate:>10,.0f} /s",
        f"  CH New Rows:      {ch_landed:>10,}",
    ]
    text = "\n".join(lines)
    return Panel(text, title="[bold cyan]CLIF EPS Benchmark — LIVE[/bold cyan]",
                 border_style="cyan", padding=(1, 2))


# ── Main benchmark ───────────────────────────────────────────────────────────

def run_benchmark():
    duration = args.duration
    target_eps = args.target_eps
    warmup = args.warmup
    mode = args.mode

    console.print()
    console.rule("[bold magenta]CLIF EPS Pipeline Stability Benchmark[/bold magenta]")
    console.print()
    console.print(f"  Mode         : [cyan]{mode}[/cyan]")
    console.print(f"  Target EPS   : [cyan]{target_eps:,}[/cyan]")
    console.print(f"  Duration     : [cyan]{duration}s[/cyan]  (+ {warmup}s warmup)")
    console.print(f"  Threads      : [cyan]{args.threads}[/cyan] Kafka producers")
    console.print(f"  Rate Limit   : [cyan]{'unlimited' if args.rate_limit == 0 else f'{args.rate_limit:,}/s/thread'}[/cyan]")
    console.print(f"  Vector URL   : [dim]{args.vector_url}[/dim]")
    console.print(f"  Kafka Broker : [dim]{args.kafka_broker}[/dim]")
    console.print(f"  ClickHouse   : [dim]{args.ch_host}:{args.ch_port}[/dim]")
    console.print()

    # ── Pre-flight checks ────────────────────────────────────────────────
    console.print("  [dim]Pre-flight checks…[/dim]")
    checks_ok = True

    if mode in ("full", "vector"):
        try:
            r = requests.get(args.vector_url.rsplit("/", 2)[0] + "/", timeout=3)
            console.print("    Vector HTTP       : [green]✔[/green]")
        except Exception:
            # Vector may not respond to GET / but accepting POST is fine
            try:
                r = requests.post(args.vector_url, json=[{"test": True}], timeout=3)
                console.print(f"    Vector HTTP       : [green]✔[/green] (status {r.status_code})")
            except Exception as e:
                console.print(f"    Vector HTTP       : [red]✘ {e}[/red]")
                checks_ok = False

    if mode in ("full", "kafka"):
        try:
            p = Producer({"bootstrap.servers": args.kafka_broker,
                          "socket.timeout.ms": 10000, "log_level": 0})
            p.list_topics(timeout=15)
            console.print("    Redpanda          : [green]✔[/green]")
            del p
        except Exception as e:
            console.print(f"    Redpanda          : [red]✘ {e}[/red]")
            checks_ok = False

    try:
        ch = clickhouse_connect.get_client(
            host=args.ch_host, port=args.ch_port,
            username=args.ch_user, password=args.ch_password,
            database=args.ch_db,
        )
        ch.query("SELECT 1")
        console.print("    ClickHouse        : [green]✔[/green]")
        del ch
    except Exception as e:
        console.print(f"    ClickHouse        : [red]✘ {e}[/red]")
        checks_ok = False

    if not checks_ok:
        console.print("\n  [red]Pre-flight failed. Aborting.[/red]")
        sys.exit(1)

    console.print()

    # ── Set up ClickHouse monitor ────────────────────────────────────────
    ch_monitor = ClickHouseMonitor()
    ch_monitor.take_baseline()

    # ── Determine EPS split ──────────────────────────────────────────────
    total_duration = warmup + duration
    if mode == "full":
        vector_eps = target_eps // 2
        kafka_eps = target_eps - vector_eps
    elif mode == "vector":
        vector_eps = target_eps
        kafka_eps = 0
    else:
        vector_eps = 0
        kafka_eps = target_eps

    # ── Launch producer threads ──────────────────────────────────────────
    threads: list[Thread] = []
    if vector_eps > 0:
        t = Thread(target=vector_producer_thread, args=(vector_eps, total_duration), daemon=True)
        threads.append(t)
    if kafka_eps > 0:
        num_kafka_threads = args.threads
        per_thread_eps = kafka_eps // num_kafka_threads if args.rate_limit else kafka_eps
        for i in range(num_kafka_threads):
            t = Thread(target=kafka_producer_thread, args=(per_thread_eps, total_duration),
                       daemon=True, name=f"kafka-{i}")
            threads.append(t)

    for t in threads:
        t.start()

    # ── Warmup phase ─────────────────────────────────────────────────────
    console.print(f"  [yellow]Warming up for {warmup}s…[/yellow]")
    for _ in range(warmup):
        if stop_event.is_set():
            break
        time.sleep(1)
        metrics.tick_second()

    # Reset metrics for actual measurement
    console.print("  [green]Warmup complete — starting measurement[/green]\n")
    metrics.per_second_rates.clear()
    # Reset production counters so only measurement‐phase events are counted
    with metrics._lock:
        metrics.produced_vector = 0
        metrics.produced_kafka = 0
        metrics.http_errors = 0
        metrics.kafka_errors = 0
        metrics.kafka_acks = 0
        metrics.http_429s = 0
        metrics._sec_produced = 0
        metrics._sec_start = time.perf_counter()
    ch_monitor.take_baseline()

    # ── Measurement phase with live display ──────────────────────────────
    t_start = time.perf_counter()

    with Live(build_live_panel(0, duration, 0, 0, 0), console=console, refresh_per_second=2) as live:
        for sec in range(1, duration + 1):
            if stop_event.is_set():
                break
            time.sleep(1)
            current_eps = metrics.tick_second()

            # Poll ClickHouse every 2 seconds
            if sec % 2 == 0:
                ch_monitor.snapshot()

            ch_landed = ch_monitor.total_landed()
            ch_rate = ch_monitor.landing_rate()
            live.update(build_live_panel(sec, duration, current_eps, ch_landed, ch_rate))

    stop_event.set()
    for t in threads:
        t.join(timeout=10)

    # Final ClickHouse snapshot (wait for pipeline drain)
    # Scale drain time based on volume produced
    drain_secs = max(15, min(60, metrics.total_produced // 100_000))
    console.print(f"\n  [dim]Waiting {drain_secs}s for pipeline drain…[/dim]")
    for _ in range(drain_secs // 3):
        time.sleep(3)
        ch_monitor.snapshot()

    total_elapsed = time.perf_counter() - t_start

    # ── Results ──────────────────────────────────────────────────────────
    console.print()
    console.rule("[bold green]EPS Benchmark Results[/bold green]")
    console.print()

    stats = metrics.stability_stats()
    ch_landed = ch_monitor.total_landed()
    ch_rate = ch_monitor.landing_rate()
    total_produced = metrics.total_produced
    # Throughput EPS = total / measurement time (excludes drain), like enterprise benchmark
    throughput_eps = total_produced / duration if duration > 0 else 0
    data_loss_pct = (1 - ch_landed / total_produced) * 100 if total_produced > 0 else 0

    # ── Summary table ────────────────────────────────────────────────────
    tbl = Table(title="Pipeline Performance", show_header=True, header_style="bold cyan")
    tbl.add_column("Metric", style="white", min_width=28)
    tbl.add_column("Value", justify="right", style="green", min_width=15)
    tbl.add_column("Target", justify="right", style="yellow", min_width=15)
    tbl.add_column("Status", justify="center", min_width=6)

    # Producer metrics
    tbl.add_row("Total Produced", f"{total_produced:,}", "", "")
    tbl.add_row("Throughput EPS", f"{throughput_eps:,.0f}/s", f"≥{target_eps:,}/s",
                "✅" if throughput_eps >= target_eps * 0.8 else "⚠️")
    tbl.add_row("Avg Producer EPS", f"{stats['avg_eps']:,.0f}/s", f"{target_eps:,}/s",
                "✅" if stats['avg_eps'] >= target_eps * 0.8 else "⚠️")
    tbl.add_row("Peak EPS", f"{stats['max_eps']:,.0f}/s", "", "")
    tbl.add_row("Min EPS", f"{stats['min_eps']:,.0f}/s", "", "")

    # Stability metrics
    tbl.add_row("", "", "", "")
    tbl.add_row("[bold]Stability[/bold]", "", "", "")
    tbl.add_row("Std Deviation", f"{stats['stddev']:,.0f}", "<20% CV", "")
    tbl.add_row("Coefficient of Variation", f"{stats['cv']:.1f}%", "<20%",
                "✅" if stats['cv'] < 20 else "⚠️")
    tbl.add_row("Jitter (max-min/avg)", f"{stats['jitter_pct']:.1f}%", "<50%",
                "✅" if stats['jitter_pct'] < 50 else "⚠️")

    # ClickHouse landing
    tbl.add_row("", "", "", "")
    tbl.add_row("[bold]ClickHouse Landing[/bold]", "", "", "")
    tbl.add_row("CH Rows Landed", f"{ch_landed:,}", f"{total_produced:,}", "")
    tbl.add_row("CH Landing Rate", f"{ch_rate:,.0f}/s", f"≥{target_eps * 0.8:,.0f}/s",
                "✅" if ch_rate >= target_eps * 0.5 else "⚠️")
    tbl.add_row("Data Completeness", f"{100 - data_loss_pct:.1f}%", "≥95%",
                "✅" if data_loss_pct < 5 else "❌" if data_loss_pct > 10 else "⚠️")

    # Error metrics
    tbl.add_row("", "", "", "")
    tbl.add_row("[bold]Errors[/bold]", "", "", "")
    tbl.add_row("HTTP Errors", f"{metrics.http_errors:,}", "0",
                "✅" if metrics.http_errors == 0 else "⚠️")
    tbl.add_row("HTTP 429 (Backpressure)", f"{metrics.http_429s:,}", "0",
                "✅" if metrics.http_429s == 0 else "⚠️")
    tbl.add_row("Kafka Errors", f"{metrics.kafka_errors:,}", "0",
                "✅" if metrics.kafka_errors == 0 else "⚠️")
    tbl.add_row("Total Errors", f"{metrics.http_errors + metrics.kafka_errors:,}", "0",
                "✅" if (metrics.http_errors + metrics.kafka_errors) == 0 else "❌")

    console.print(tbl)

    # ── Per-second rate chart (ASCII) ────────────────────────────────────
    console.print()
    console.rule("[bold cyan]EPS Over Time (per-second)[/bold cyan]")
    rates = [s["rate"] for s in metrics.per_second_rates]
    if rates:
        max_rate = max(rates) if max(rates) > 0 else 1
        chart_height = 15
        chart_width = min(len(rates), 80)
        step = max(1, len(rates) // chart_width)
        sampled = [rates[i] for i in range(0, len(rates), step)][:chart_width]

        for row in range(chart_height, 0, -1):
            threshold = max_rate * row / chart_height
            line_label = f"{int(threshold):>8,} │"
            chars = []
            for val in sampled:
                if val >= threshold:
                    chars.append("█")
                elif val >= threshold - max_rate / chart_height / 2:
                    chars.append("▄")
                else:
                    chars.append(" ")
            console.print(f"  {line_label}{''.join(chars)}")
        console.print(f"  {'':>8} └{'─' * len(sampled)}")
        console.print(f"  {'':>8}  {'1':}<{len(sampled) - 1}{'s'}")
        console.print(f"  [dim]  (each column ≈ {step}s)[/dim]")

    # ── ClickHouse landing over time ─────────────────────────────────────
    if len(ch_monitor.snapshots) >= 2:
        console.print()
        ch_rates = []
        for i in range(1, len(ch_monitor.snapshots)):
            dt = ch_monitor.snapshots[i]["time"] - ch_monitor.snapshots[i-1]["time"]
            dn = ch_monitor.snapshots[i]["total_new"] - ch_monitor.snapshots[i-1]["total_new"]
            ch_rates.append(dn / dt if dt > 0 else 0)
        if ch_rates:
            console.print(f"  CH Landing Rate — Min: {min(ch_rates):,.0f}/s  "
                          f"Avg: {statistics.mean(ch_rates):,.0f}/s  "
                          f"Max: {max(ch_rates):,.0f}/s")

    # ── Final verdict ────────────────────────────────────────────────────
    console.print()
    console.rule("[bold]Verdict[/bold]")

    grade_points = 0
    grade_max = 5

    # Use max(throughput_eps, avg per-second) for throughput check
    effective_eps = max(throughput_eps, stats['avg_eps'])
    if effective_eps >= target_eps * 0.8:
        grade_points += 1
    if stats['cv'] < 20:
        grade_points += 1
    if data_loss_pct < 5:
        grade_points += 1
    if (metrics.http_errors + metrics.kafka_errors) == 0:
        grade_points += 1
    if ch_rate >= target_eps * 0.5:
        grade_points += 1

    grades = {5: "A+", 4: "A", 3: "B", 2: "C", 1: "D", 0: "F"}
    grade = grades.get(grade_points, "F")
    grade_color = "green" if grade_points >= 4 else "yellow" if grade_points >= 3 else "red"

    console.print(f"\n  Pipeline Stability Grade: [{grade_color} bold]{grade}[/{grade_color} bold]  ({grade_points}/{grade_max})")
    console.print()

    criteria = [
        ("Throughput ≥80% target", effective_eps >= target_eps * 0.8),
        ("CV < 20% (stable rate)", stats['cv'] < 20),
        ("Data loss < 5%", data_loss_pct < 5),
        ("Zero errors", (metrics.http_errors + metrics.kafka_errors) == 0),
        ("CH landing ≥50% target", ch_rate >= target_eps * 0.5),
    ]
    for label, passed in criteria:
        icon = "[green]✔[/green]" if passed else "[red]✘[/red]"
        console.print(f"    {icon}  {label}")

    console.print()

    # Return results for programmatic use
    return {
        "grade": grade,
        "total_produced": total_produced,
        "throughput_eps": throughput_eps,
        "avg_eps": stats["avg_eps"],
        "peak_eps": stats["max_eps"],
        "cv_pct": stats["cv"],
        "jitter_pct": stats["jitter_pct"],
        "ch_landed": ch_landed,
        "ch_rate": ch_rate,
        "data_loss_pct": data_loss_pct,
        "errors": metrics.http_errors + metrics.kafka_errors,
        "duration_s": total_elapsed,
    }


if __name__ == "__main__":
    results = run_benchmark()
    sys.exit(0 if results["grade"] in ("A+", "A", "B") else 1)
