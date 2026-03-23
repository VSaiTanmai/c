#!/usr/bin/env python3
"""
CLIF High-Throughput Sysmon Event Producer
==========================================
Max-speed producer for Redpanda, optimised for sustained >50K EPS per process.

Optimisations:
  • orjson (~6× faster than json.dumps)
  • Pre-computed data pools (tuples → faster random.choice)
  • Cached timestamps (refreshed every 500 calls)
  • Function aliasing to skip attribute lookups
  • Pre-batched topic selection via random.choices(k=5000)
  • Max-speed tight loop — NO per-event sleep
  • Kafka: acks=1, lz4, 100K batch, 2MB batch.size, 4M queue buffer

Usage:
    python run_sysmon_eps_demo.py                      # unlimited, run forever
    python run_sysmon_eps_demo.py --duration 120        # run for 2 minutes
    python run_sysmon_eps_demo.py --rate-limit 50000    # cap at 50K EPS
    python run_sysmon_eps_demo.py --broker localhost:19092
"""

from __future__ import annotations

import argparse
import random
import signal
import sys
import time
from datetime import datetime, timezone
from threading import Event

# ── Fast JSON ────────────────────────────────────────────────────────────────
try:
    import orjson
    _fast_dumps = orjson.dumps       # returns bytes directly
except ImportError:
    import json
    def _fast_dumps(obj):            # type: ignore[misc]
        return json.dumps(obj).encode()

# ── CLI ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="CLIF High-Throughput Sysmon Producer")
parser.add_argument("--broker", default="localhost:19092", help="Redpanda broker (default: localhost:19092)")
parser.add_argument("--duration", type=int, default=0, help="Run duration in seconds (0 = infinite)")
parser.add_argument("--rate-limit", type=int, default=0, help="Max EPS cap (0 = unlimited)")
parser.add_argument("--eps", type=int, default=0, help="Alias for --rate-limit")
args = parser.parse_args()

BROKER = args.broker
DURATION = args.duration
RATE_LIMIT = args.rate_limit or args.eps  # --eps is backwards-compat alias

# ── Graceful shutdown ────────────────────────────────────────────────────────
_stop = Event()

def _sigint(sig, frame):
    print("\n[!] Ctrl+C — flushing and stopping…")
    _stop.set()

signal.signal(signal.SIGINT, _sigint)

# ── Pre-computed data pools (tuples for speed) ──────────────────────────────

_IPS = tuple(f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
             for _ in range(500))
_HOSTS = tuple(f"WS-{i:04d}" for i in range(20))
_USERS = tuple(f"user_{i:03d}" for i in range(50))
_MITRE = (
    "T1059.001", "T1053.005", "T1547.001", "T1055.012",
    "T1021.001", "T1003.001", "T1071.001", "T1048.003",
)
_CATEGORIES = ("auth", "malware", "exfiltration", "brute-force", "scan", "lateral-movement")
_BINARIES = (
    "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\powershell.exe",
    "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\rundll32.exe",
    "C:\\Program Files\\app\\agent.exe", "C:\\Windows\\System32\\conhost.exe",
    "C:\\Windows\\System32\\wscript.exe", "C:\\Windows\\System32\\mshta.exe",
)
_SYSCALLS = ("NtCreateProcess", "NtCreateFile", "NtOpenProcess", "NtWriteVirtualMemory")
_EXIT_CODES = (0, 0, 0, 0, 1, 137, -1)
_PORTS = (22, 80, 443, 8080, 53, 3306, 5432, 6379, 9092, 445, 3389, 8443)
_PROTOS = ("TCP", "TCP", "TCP", "UDP", "UDP")
_DIRS = ("inbound", "outbound")
_GEOS = ("US", "US", "US", "CN", "RU", "DE", "GB", "IN", "BR", "")
_DNS = tuple(f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(4,10)))}.{'com' if random.random() < 0.5 else 'net'}"
             for _ in range(100))
_SEVS = ("INFO", "INFO", "INFO", "WARN", "WARN", "ERROR", "CRITICAL")
_ACTIONS = ("allow", "deny", "drop", "alert")
_SOURCES = ("sysmon", "winlogbeat", "auditd", "firewall", "ids-sensor", "edr-agent")

# ── Fast timestamp ──────────────────────────────────────────────────────────
_UTC = timezone.utc
_ts_cache: str = ""
_ts_counter: int = 0

def _now_iso() -> str:
    global _ts_cache, _ts_counter
    _ts_counter += 1
    if _ts_counter % 500 == 0 or not _ts_cache:
        _ts_cache = datetime.now(_UTC).isoformat()
    return _ts_cache


# ── Event generators ─────────────────────────────────────────────────────────

def _gen_raw() -> dict:
    return {
        "timestamp": _now_iso(),
        "level": random.choice(_SEVS),
        "source": random.choice(_SOURCES),
        "message": f"[{random.choice(_SOURCES)}] {random.choice(_HOSTS)}: "
                   f"action={random.choice(_ACTIONS)} "
                   f"src={random.choice(_IPS)} dst={random.choice(_IPS)} "
                   f"bytes={random.randint(64, 65536)}",
        "metadata": {"ip_address": random.choice(_IPS)},
    }

def _gen_security() -> dict:
    return {
        "timestamp": _now_iso(),
        "severity": random.randint(0, 4),
        "category": random.choice(_CATEGORIES),
        "source": random.choice(_SOURCES),
        "description": f"Sysmon alert from {random.choice(_HOSTS)}: {random.choice(_ACTIONS)}",
        "user_id": random.choice(_USERS),
        "ip_address": random.choice(_IPS),
        "hostname": random.choice(_HOSTS),
        "mitre_tactic": random.choice(_MITRE),
        "mitre_technique": f"T{random.randint(1000,1999)}",
        "ai_confidence": round(random.uniform(0.1, 0.99), 2),
        "metadata": {},
    }

def _gen_process() -> dict:
    return {
        "timestamp": _now_iso(),
        "hostname": random.choice(_HOSTS),
        "pid": random.randint(1, 65535),
        "ppid": random.randint(1, 65535),
        "uid": random.randint(0, 65534),
        "gid": random.randint(0, 65534),
        "binary_path": random.choice(_BINARIES),
        "arguments": f"--user {random.choice(_USERS)}",
        "cwd": "C:\\Users\\Default",
        "exit_code": random.choice(_EXIT_CODES),
        "syscall": random.choice(_SYSCALLS),
        "is_suspicious": 1 if random.random() < 0.005 else 0,
        "metadata": {},
    }

def _gen_network() -> dict:
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
        "dns_query": random.choice(_DNS),
        "geo_country": random.choice(_GEOS),
        "is_suspicious": 1 if random.random() < 0.005 else 0,
        "metadata": {},
    }


# ── Topic routing ────────────────────────────────────────────────────────────
TOPICS = ("security-events", "process-events", "network-events", "raw-logs")
TOPIC_WEIGHTS = (0.25, 0.25, 0.25, 0.25)
_GENERATORS = {
    "security-events": _gen_security,
    "process-events":  _gen_process,
    "network-events":  _gen_network,
    "raw-logs":        _gen_raw,
}

# ── Kafka Producer ──────────────────────────────────────────────────────────
from confluent_kafka import Producer

_conf = {
    "bootstrap.servers":             BROKER,
    "acks":                          "1",
    "compression.type":              "lz4",
    "batch.num.messages":            100_000,
    "batch.size":                    2_097_152,        # 2 MB
    "linger.ms":                     5,
    "queue.buffering.max.messages":  4_000_000,
    "queue.buffering.max.kbytes":    4_194_304,        # 4 GB
    "enable.idempotence":            False,
    "request.timeout.ms":            30_000,
    "message.timeout.ms":            60_000,
    "log_level":                     3,                # WARN only
}
_producer = Producer(_conf)

# ── Function aliasing (avoid attribute lookups in hot loop) ─────────────────
_produce = _producer.produce
_poll    = _producer.poll
_perf    = time.perf_counter
_dumps   = _fast_dumps
_choices = random.choices
_choice  = random.choice

# ── Main loop ───────────────────────────────────────────────────────────────

def main() -> None:
    print(f"╔══════════════════════════════════════════════════════╗")
    print(f"║   CLIF High-Throughput Sysmon Producer              ║")
    print(f"╠══════════════════════════════════════════════════════╣")
    print(f"║ Broker    : {BROKER:<40} ║")
    print(f"║ Duration  : {'infinite' if DURATION == 0 else f'{DURATION}s':<40} ║")
    print(f"║ Rate Limit: {'unlimited' if RATE_LIMIT == 0 else f'{RATE_LIMIT:,} eps':<40} ║")
    print(f"║ Topics    : {', '.join(TOPICS):<40} ║")
    print(f"╚══════════════════════════════════════════════════════╝")
    print()

    total = 0
    errors = 0
    start = _perf()
    last_print = start
    batch_count = 0

    # Pre-batch topic selection chunk size
    CHUNK = 5000
    topic_batch = _choices(TOPICS, weights=TOPIC_WEIGHTS, k=CHUNK)
    batch_idx = 0

    deadline = start + DURATION if DURATION > 0 else float("inf")

    while not _stop.is_set():
        now = _perf()
        if now >= deadline:
            break

        # Rate limiting (if enabled)
        if RATE_LIMIT > 0:
            elapsed = now - start
            if elapsed > 0 and total / elapsed >= RATE_LIMIT:
                _poll(0)
                time.sleep(0.0001)
                continue

        # Pick topic from pre-batched selection
        topic = topic_batch[batch_idx]
        batch_idx += 1
        if batch_idx >= CHUNK:
            topic_batch = _choices(TOPICS, weights=TOPIC_WEIGHTS, k=CHUNK)
            batch_idx = 0

        # Generate and produce
        gen = _GENERATORS[topic]
        payload = _dumps(gen())

        for attempt in range(5):
            try:
                _produce(topic, payload)
                break
            except BufferError:
                _poll(100)
                if attempt == 4:
                    errors += 1
        else:
            continue

        total += 1
        batch_count += 1

        # Poll for delivery callbacks every 5000 events
        if batch_count >= 5000:
            _poll(0)
            batch_count = 0

        # Status print every 50K events
        if total % 50_000 == 0:
            now2 = _perf()
            elapsed = now2 - start
            instant_eps = 50_000 / max(now2 - last_print, 0.001)
            avg_eps = total / max(elapsed, 0.001)
            print(f"  [{elapsed:7.1f}s] total={total:>10,}  "
                  f"instant={instant_eps:>8,.0f} eps  "
                  f"avg={avg_eps:>8,.0f} eps  "
                  f"errors={errors}")
            last_print = now2

    # Flush remaining
    elapsed = _perf() - start
    print(f"\n  Flushing producer queue…")
    remaining = _producer.flush(timeout=30)
    final = _perf() - start

    avg_eps = total / max(elapsed, 0.001)
    print()
    print(f"╔══════════════════════════════════════════════════════╗")
    print(f"║   RESULTS                                           ║")
    print(f"╠══════════════════════════════════════════════════════╣")
    print(f"║ Total Events : {total:>12,}                          ║")
    print(f"║ Duration     : {elapsed:>12.1f}s                         ║")
    print(f"║ Avg EPS      : {avg_eps:>12,.0f}                          ║")
    print(f"║ Errors       : {errors:>12,}                          ║")
    print(f"║ Unflushed    : {remaining:>12,}                          ║")
    print(f"╚══════════════════════════════════════════════════════╝")


if __name__ == "__main__":
    main()
