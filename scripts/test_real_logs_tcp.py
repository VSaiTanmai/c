#!/usr/bin/env python3
"""
CLIF Real-Log TCP Socket Throughput Test
=========================================
Same real-log datasets as test_real_logs.py but sends via persistent TCP
socket (NDJSON) instead of HTTP POST. This eliminates HTTP framing overhead
and measures Vector's raw per-event processing speed.

Usage:
  python scripts/test_real_logs_tcp.py [--duration 60] [--workers 6]
         [--host localhost] [--port 9514] [--max-per-dataset 5000]
"""

import argparse
import json
import multiprocessing
import socket
import sys
import time
from collections import defaultdict
from pathlib import Path

# Reuse dataset loading from the HTTP test
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_real_logs import load_all_datasets, get_clickhouse_counts

TABLES = ["raw_logs", "security_events", "process_events", "network_events"]


def build_ndjson_blocks(all_events: dict, block_size: int = 500):
    """
    Interleave events from all datasets and pre-serialize into NDJSON blocks.
    Each block is a bytes object of `block_size` newline-delimited JSON events.
    Returns list of (block_bytes, count, type_counts).
    """
    # Interleave round-robin
    names = list(all_events.keys())
    iterators = {n: iter(all_events[n]) for n in names}
    interleaved = []
    done = set()
    while len(done) < len(names):
        for n in names:
            if n in done:
                continue
            try:
                ev = next(iterators[n])
                interleaved.append((n, ev))
            except StopIteration:
                done.add(n)

    # Build blocks
    blocks = []
    for i in range(0, len(interleaved), block_size):
        chunk = interleaved[i:i + block_size]
        lines = []
        type_counts = defaultdict(int)
        for name, ev in chunk:
            lines.append(json.dumps(ev, separators=(",", ":")))
            type_counts[name] += 1
        block_bytes = ("\n".join(lines) + "\n").encode("utf-8")
        blocks.append((block_bytes, len(chunk), dict(type_counts)))
    return blocks


def tcp_worker_fn(args):
    """Send NDJSON events over persistent TCP socket. Runs in child process."""
    worker_id, blocks, host, port, duration, warmup, result_queue = args

    sent = 0
    errors = 0
    type_stats = defaultdict(int)

    # Persistent TCP connection
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        sock.settimeout(10)
        sock.connect((host, port))
    except Exception as e:
        result_queue.put({
            "worker_id": worker_id,
            "sent": 0,
            "errors": 1,
            "type_stats": {},
            "error_msg": str(e),
        })
        return

    start = time.monotonic()
    warmup_end = start + warmup
    measure_end = warmup_end + duration

    block_idx = 0
    n_blocks = len(blocks)

    while True:
        now = time.monotonic()
        if now >= measure_end:
            break

        block_bytes, count, tcounts = blocks[block_idx % n_blocks]
        block_idx += 1

        try:
            sock.sendall(block_bytes)
            if now >= warmup_end:
                sent += count
                for k, v in tcounts.items():
                    type_stats[k] += v
        except Exception:
            if now >= warmup_end:
                errors += 1
            # Reconnect
            try:
                sock.close()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
                sock.settimeout(10)
                sock.connect((host, port))
            except Exception:
                pass

    try:
        sock.close()
    except Exception:
        pass

    result_queue.put({
        "worker_id": worker_id,
        "sent": sent,
        "errors": errors,
        "type_stats": dict(type_stats),
    })


def main():
    parser = argparse.ArgumentParser(description="CLIF Real-Log TCP Socket Test")
    parser.add_argument("--duration", type=int, default=60, help="Test duration (seconds)")
    parser.add_argument("--workers", type=int, default=6, help="Number of TCP connections")
    parser.add_argument("--warmup", type=int, default=5, help="Warmup seconds")
    parser.add_argument("--max-per-dataset", type=int, default=5000,
                        help="Max events per dataset")
    parser.add_argument("--host", default="localhost", help="Vector TCP host")
    parser.add_argument("--port", type=int, default=9514, help="Vector TCP NDJSON port")
    parser.add_argument("--block-size", type=int, default=500,
                        help="Events per NDJSON block")
    args = parser.parse_args()

    print("═" * 65)
    print("  CLIF Real-Log TCP Socket Throughput Test")
    print("═" * 65)
    print(f"  Duration:     {args.duration}s")
    print(f"  Workers:      {args.workers} persistent TCP connections")
    print(f"  Block size:   {args.block_size} events/block")
    print(f"  Warmup:       {args.warmup}s")
    print(f"  Endpoint:     tcp://{args.host}:{args.port}")
    print("─" * 65)

    # ── Check Vector TCP reachability ────────────────────────────────────
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((args.host, args.port))
        s.sendall(b'{"message":"healthcheck","source_type":"test"}\n')
        time.sleep(0.1)
        s.close()
        print("  ✔ Vector TCP socket reachable")
    except Exception as e:
        print(f"  ✘ Vector TCP unreachable at {args.host}:{args.port}: {e}")
        sys.exit(1)

    # ── Load datasets ────────────────────────────────────────────────────
    print("\n  Loading real log datasets...")
    all_events = load_all_datasets(args.max_per_dataset)
    total_events = sum(len(v) for v in all_events.values())
    print(f"\n  Total: {total_events:,} events from {len(all_events)} datasets")

    if total_events == 0:
        print("  ✘ No events loaded — cannot test")
        sys.exit(1)

    # ── Build NDJSON blocks ──────────────────────────────────────────────
    print(f"\n  Building NDJSON blocks (block_size={args.block_size})...")
    blocks = build_ndjson_blocks(all_events, args.block_size)
    total_payload_mb = sum(len(b[0]) for b in blocks) / (1024 * 1024)
    print(f"  ✔ {len(blocks):,} blocks, {total_payload_mb:.1f} MB total payload")

    # ── Split blocks among workers ───────────────────────────────────────
    worker_blocks = [[] for _ in range(args.workers)]
    for i, block in enumerate(blocks):
        worker_blocks[i % args.workers].append(block)

    # ── Get ClickHouse baseline ──────────────────────────────────────────
    print("\n  Recording ClickHouse baseline counts...")
    ch_before = get_clickhouse_counts()
    for t, c in ch_before.items():
        if isinstance(c, int):
            print(f"    {t:25s}  {c:>12,}")
        else:
            print(f"    {t:25s}  {c}")

    # ── Start workers ────────────────────────────────────────────────────
    print(f"\n  Starting {args.workers} TCP worker processes...")
    result_queue = multiprocessing.Manager().Queue()

    worker_args = [
        (i, worker_blocks[i], args.host, args.port,
         args.duration, args.warmup, result_queue)
        for i in range(args.workers)
    ]

    t_start = time.monotonic()

    pool = multiprocessing.Pool(processes=args.workers)
    async_results = pool.map_async(tcp_worker_fn, worker_args)

    # ── Progress ─────────────────────────────────────────────────────────
    print(f"  ⏳ Warmup ({args.warmup}s)...\n")
    total_wait = args.warmup + args.duration + 5
    print("  📊 Measuring ({0}s)...".format(args.duration))
    print("       Sec        Status")
    print("  " + "─" * 31)

    for sec in range(5, total_wait + 1, 5):
        time.sleep(5)
        if async_results.ready():
            break
        print(f"  {sec:>8}    running...")

    async_results.wait(timeout=30)
    pool.close()
    pool.join()

    t_end = time.monotonic()
    wall = t_end - t_start

    # ── Collect results ──────────────────────────────────────────────────
    total_sent = 0
    total_errors = 0
    merged_types = defaultdict(int)

    while not result_queue.empty():
        r = result_queue.get()
        total_sent += r["sent"]
        total_errors += r["errors"]
        for k, v in r.get("type_stats", {}).items():
            merged_types[k] += v

    avg_eps = total_sent / (wall - args.warmup) if wall > args.warmup else 0

    # ── Print results ────────────────────────────────────────────────────
    print("\n" + "═" * 65)
    print("  RESULTS (TCP NDJSON)")
    print("═" * 65)
    print(f"  Total events sent:     {total_sent:>12,}")
    print(f"  Duration:              {wall:>12.1f}s")
    print(f"  Avg EPS:               {avg_eps:>12,.0f}")
    print(f"  Errors:                {total_errors:>12,}")
    print(f"  Workers:               {args.workers:>12}")

    print("\n  Events by Log Type:")
    print("  " + "─" * 55)
    for name in sorted(merged_types, key=lambda x: -merged_types[x]):
        c = merged_types[name]
        ds = next((d for dn, d in __import__("test_real_logs", fromlist=["DATASETS"]).DATASETS.items()
                    if dn == name), None)
        cat = ds.get("log_category", "?") if ds else "?"
        pct = 100 * c / total_sent if total_sent else 0
        print(f"    {name:25s}  {c:>10,}  ({pct:5.1f}%)  [{cat}]")
    print("  " + "─" * 55)

    # ── ClickHouse verification ──────────────────────────────────────────
    print(f"\n  ⏳ Waiting 15s for Redpanda → ClickHouse consumer flush...")
    time.sleep(15)

    print("\n  ClickHouse Event Delivery Verification:")
    print("  " + "─" * 65)
    print(f"    {'Table':30s}  {'Before':>12}  {'After':>12}  {'New':>12}")
    print("  " + "─" * 65)
    ch_after = get_clickhouse_counts()
    total_new = 0
    for t in TABLES:
        before = ch_before.get(t, 0)
        after = ch_after.get(t, 0)
        if isinstance(before, int) and isinstance(after, int):
            new = after - before
            total_new += new
            mark = "✔" if new > 0 else "✘"
            print(f"  {mark} {t:30s}  {before:>12,}  {after:>12,}  {new:>12,}")
        else:
            print(f"  ✘ {t:30s}  {before!s:>12}  {after!s:>12}  {'?':>12}")
    print("  " + "─" * 65)
    print(f"    TOTAL NEW {'':30s}{total_new:>12,}")

    if total_sent > 0:
        dr = total_new / total_sent * 100
        print(f"\n  📦 Delivery Rate: {total_new:,} / {total_sent:,} = {dr:.1f}%")
        if dr == 0:
            print("  ⚠ NOTE — Consumers may be stopped; data is in Redpanda queues")

    print(f"\n{'═' * 65}")
    print(f"  📊 Result: {avg_eps:,.0f} EPS via TCP NDJSON with REAL logs")
    print(f"     (compare to HTTP JSON test for protocol overhead delta)")
    print(f"{'═' * 65}")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
