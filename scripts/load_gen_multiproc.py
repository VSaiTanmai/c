#!/usr/bin/env python3
"""
CLIF Multi-Process Load Generator
===================================
Uses multiprocessing to bypass Python GIL for true parallel HTTP sending.
Each worker process runs its own HTTP connection pool to Vector.

Usage:
  python scripts/load_gen_multiproc.py                    # Default: 200k EPS, 30s
  python scripts/load_gen_multiproc.py --eps 100000       # Custom target
  python scripts/load_gen_multiproc.py --duration 60      # 60 second test
  python scripts/load_gen_multiproc.py --workers 12       # 12 parallel processes
"""

import argparse
import json
import multiprocessing
import os
import random
import socket
import struct
import sys
import time
from multiprocessing import Process, Value, Array

VECTOR_HOST = os.getenv("VECTOR_HTTP_HOST", "localhost")
VECTOR_PORT = int(os.getenv("VECTOR_HTTP_PORT", "8687"))

# ── Pre-built event templates (varied types for realistic routing) ───────
TEMPLATES = [
    # ~40% raw logs
    {"message": "Application startup complete in 342ms", "source": "myapp", "level": "INFO", "hostname": "app-srv-01"},
    {"message": "Cache miss ratio: 12.3% over last 60s", "source": "redis", "level": "INFO", "hostname": "cache-01"},
    {"message": "Garbage collection paused 45ms", "source": "jvm", "level": "WARNING", "hostname": "app-srv-02"},
    {"message": "Configuration reloaded successfully", "source": "nginx", "level": "INFO", "hostname": "web-01"},
    # ~20% security events
    {"message": "Failed password for root from 10.0.1.55 port 22 ssh2", "source": "sshd", "level": "WARNING", "hostname": "bastion-01"},
    {"message": "Accepted publickey for deploy from 10.0.2.10 port 54321 ssh2", "source": "sshd", "level": "INFO", "hostname": "bastion-01"},
    # ~20% process events
    {"message": "Process started", "pid": 12345, "ppid": 1, "uid": 1000, "binary_path": "/usr/bin/python3", "hostname": "worker-01"},
    {"message": "Process exited", "pid": 5678, "ppid": 100, "uid": 0, "binary_path": "/usr/sbin/cron", "exit_code": 0, "hostname": "scheduler-01"},
    # ~20% network events
    {"message": "TCP connection established", "src_ip": "10.0.1.100", "dst_ip": "192.168.1.50", "src_port": 44231, "dst_port": 443, "protocol": "TCP", "hostname": "proxy-01"},
    {"message": "DNS query resolved", "src_ip": "10.0.1.200", "dst_ip": "8.8.8.8", "src_port": 53211, "dst_port": 53, "protocol": "UDP", "dns_query": "api.example.com", "hostname": "resolver-01"},
]


def build_batch_payload(batch_size: int) -> bytes:
    """Pre-build a batch payload for reuse (avoids per-send serialization)."""
    events = []
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    for i in range(batch_size):
        evt = TEMPLATES[i % len(TEMPLATES)].copy()
        evt["timestamp"] = ts
        events.append(evt)
    return json.dumps(events).encode("utf-8")


def worker_process(worker_id: int, shared_sent: Value, shared_errors: Value,
                   target_eps: int, batch_size: int, running: Value, warmup_done: Value):
    """Single worker process that sends HTTP POSTs to Vector."""
    import http.client

    batches_per_sec = max(1, target_eps // batch_size)
    interval = 1.0 / batches_per_sec

    # Pre-build payload (reuse same bytes — Vector dedup will handle duplicates)
    payload = build_batch_payload(batch_size)
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(payload)),
    }

    conn = http.client.HTTPConnection(VECTOR_HOST, VECTOR_PORT, timeout=10)
    local_sent = 0
    local_errors = 0

    while running.value:
        try:
            t0 = time.monotonic()
            conn.request("POST", "/v1/logs", body=payload, headers=headers)
            resp = conn.getresponse()
            _ = resp.read()

            if resp.status in (200, 201, 204):
                local_sent += batch_size
                # Batch atomic update every 10 sends to reduce lock contention
                if local_sent % (batch_size * 10) == 0:
                    with shared_sent.get_lock():
                        shared_sent.value += batch_size * 10
            else:
                local_errors += 1

            elapsed = time.monotonic() - t0
            sleep_time = interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

        except Exception:
            local_errors += 1
            try:
                conn.close()
            except Exception:
                pass
            conn = http.client.HTTPConnection(VECTOR_HOST, VECTOR_PORT, timeout=10)
            time.sleep(0.05)

    # Final flush of remaining count
    remainder = local_sent % (batch_size * 10)
    if remainder > 0:
        with shared_sent.get_lock():
            shared_sent.value += remainder
    with shared_errors.get_lock():
        shared_errors.value += local_errors

    try:
        conn.close()
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="CLIF Multi-Process Load Generator")
    parser.add_argument("--eps", type=int, default=200_000, help="Target EPS (default: 200000)")
    parser.add_argument("--duration", type=int, default=30, help="Test duration in seconds (default: 30)")
    parser.add_argument("--workers", type=int, default=0, help="Worker processes (default: CPU count)")
    parser.add_argument("--batch", type=int, default=500, help="Events per HTTP batch (default: 500)")
    parser.add_argument("--warmup", type=int, default=5, help="Warmup seconds (default: 5)")
    args = parser.parse_args()

    num_workers = args.workers or min(multiprocessing.cpu_count(), 16)
    eps_per_worker = args.eps // num_workers
    batch_size = args.batch

    print(f"\n{'═' * 60}")
    print(f"  CLIF Multi-Process Load Generator")
    print(f"{'═' * 60}")
    print(f"  Target EPS:     {args.eps:>12,}")
    print(f"  Workers:        {num_workers:>12}")
    print(f"  EPS/worker:     {eps_per_worker:>12,}")
    print(f"  Batch size:     {batch_size:>12}")
    print(f"  Duration:       {args.duration:>12}s")
    print(f"  Warmup:         {args.warmup:>12}s")
    print(f"  Endpoint:       http://{VECTOR_HOST}:{VECTOR_PORT}/v1/logs")
    print(f"{'═' * 60}\n")

    # Check connectivity
    try:
        sock = socket.create_connection((VECTOR_HOST, VECTOR_PORT), timeout=5)
        sock.close()
        print(f"  ✔ Vector reachable at {VECTOR_HOST}:{VECTOR_PORT}")
    except Exception as e:
        print(f"  ✘ Cannot reach Vector: {e}")
        return 1

    # Shared state
    shared_sent = Value('q', 0)      # unsigned long long
    shared_errors = Value('q', 0)
    running = Value('b', 1)          # bool
    warmup_done = Value('b', 0)

    # Launch workers
    processes = []
    for i in range(num_workers):
        p = Process(target=worker_process,
                    args=(i, shared_sent, shared_errors, eps_per_worker, batch_size, running, warmup_done))
        p.daemon = True
        processes.append(p)

    print(f"\n  Starting {num_workers} worker processes...")
    for p in processes:
        p.start()

    # Warmup
    print(f"  ⏳ Warmup ({args.warmup}s)...", end="", flush=True)
    time.sleep(args.warmup)
    warmup_sent = shared_sent.value
    print(f" {warmup_sent:,} events sent during warmup")

    # Reset counters for measurement
    with shared_sent.get_lock():
        shared_sent.value = 0
    with shared_errors.get_lock():
        shared_errors.value = 0

    # Measurement
    print(f"\n  📊 Measuring ({args.duration}s)...")
    print(f"  {'Sec':>5}  {'Instant EPS':>14}  {'Cumulative':>14}  {'Avg EPS':>12}")
    print(f"  {'─' * 52}")

    measure_start = time.monotonic()
    samples = []

    for sec in range(1, args.duration + 1):
        prev = shared_sent.value
        time.sleep(1.0)
        curr = shared_sent.value
        instant_eps = curr - prev
        samples.append(instant_eps)
        elapsed = time.monotonic() - measure_start
        avg = curr / elapsed if elapsed > 0 else 0
        print(f"  {sec:>5}  {instant_eps:>14,}  {curr:>14,}  {avg:>12,.0f}")

    measure_elapsed = time.monotonic() - measure_start

    # Stop workers
    running.value = 0
    for p in processes:
        p.join(timeout=5)

    total_sent = shared_sent.value
    total_errors = shared_errors.value
    avg_eps = total_sent / measure_elapsed if measure_elapsed > 0 else 0
    peak_eps = max(samples) if samples else 0
    p50_eps = sorted(samples)[len(samples) // 2] if samples else 0
    p95_idx = int(len(samples) * 0.95) if samples else 0
    p95_eps = sorted(samples)[min(p95_idx, len(samples) - 1)] if samples else 0
    min_eps = min(samples) if samples else 0

    print(f"\n  {'═' * 52}")
    print(f"  RESULTS")
    print(f"  {'═' * 52}")
    print(f"  Total events:    {total_sent:>14,}")
    print(f"  Duration:        {measure_elapsed:>14.1f}s")
    print(f"  Avg EPS:         {avg_eps:>14,.0f}")
    print(f"  Peak EPS:        {peak_eps:>14,}")
    print(f"  P50 EPS:         {p50_eps:>14,}")
    print(f"  P95 EPS:         {p95_eps:>14,}")
    print(f"  Min EPS:         {min_eps:>14,}")
    print(f"  Errors:          {total_errors:>14,}")
    print(f"  Target EPS:      {args.eps:>14,}")
    print(f"  {'═' * 52}")

    ratio = avg_eps / args.eps if args.eps > 0 else 0
    if ratio >= 0.9:
        print(f"\n  ✔ PASS — {ratio:.1%} of target ({avg_eps:,.0f} / {args.eps:,} EPS)")
    elif ratio >= 0.7:
        print(f"\n  ⚠ WARN — {ratio:.1%} of target ({avg_eps:,.0f} / {args.eps:,} EPS)")
    else:
        print(f"\n  ✘ FAIL — {ratio:.1%} of target ({avg_eps:,.0f} / {args.eps:,} EPS)")

    # Resource observation
    print(f"\n  💡 If throughput < target, check:")
    print(f"     1. docker stats clif-vector — is CPU at limit?")
    print(f"     2. This machine's total CPU cores vs load gen + Vector overhead")
    print(f"     3. Network loopback bandwidth (usually not a factor)")
    print(f"     4. Vector API: http://localhost:8686/api/v1/graph")
    print()

    return 0 if ratio >= 0.7 else 1


if __name__ == "__main__":
    sys.exit(main())
