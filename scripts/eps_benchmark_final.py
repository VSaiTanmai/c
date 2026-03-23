#!/usr/bin/env python3
"""
CLIF Final Production E2E Benchmark
====================================
Sends pre-built real-log NDJSON payload via parallel TCP sockets to Vector,
then verifies end-to-end delivery through Redpanda → Consumer → ClickHouse.

Uses the 277.6 MB real_logs_payload.ndjson (1M+ events from 11 datasets).

Usage:
  python scripts/eps_benchmark_final.py [--duration 60] [--workers 6]
"""

import argparse
import multiprocessing
import os
import socket
import sys
import time
from pathlib import Path

# ── Configuration ────────────────────────────────────────────────────────────

PAYLOAD_PATH = Path(r"C:\CLIF\tools\tcpblaster\real_logs_payload.ndjson")
ALT_PAYLOAD = Path(r"C:\CLIF\benchmark_payload.ndjson")

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_NATIVE_PORT", "9000"))
CLICKHOUSE_HTTP_PORT = int(os.getenv("CLICKHOUSE_HTTP_PORT", "8123"))
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "clif_admin")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "Cl1f_Ch@ngeM3_2026!")
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "clif_logs")

TABLES = ["raw_logs", "security_events", "process_events", "network_events"]


def get_ch_counts():
    """Get row counts from all 4 ClickHouse tables via HTTP API."""
    import urllib.request
    import json as _json
    counts = {}
    for table in TABLES:
        url = (
            f"http://{CLICKHOUSE_HOST}:{CLICKHOUSE_HTTP_PORT}"
            f"/?user={CLICKHOUSE_USER}&password={CLICKHOUSE_PASSWORD}"
            f"&database={CLICKHOUSE_DB}"
            f"&query=SELECT+count()+FROM+{table}+FORMAT+JSON"
        )
        try:
            resp = urllib.request.urlopen(url, timeout=10)
            data = _json.loads(resp.read())
            counts[table] = int(data["data"][0]["count()"])
        except Exception as e:
            counts[table] = f"ERROR: {e}"
    return counts


def load_payload(path: Path):
    """Load NDJSON file into memory, count lines, split into chunks."""
    print(f"  Loading {path.name} ({path.stat().st_size / 1024 / 1024:.1f} MB)...")
    raw = path.read_bytes()
    line_count = raw.count(b"\n")
    # Split into ~256KB chunks for efficient TCP sends
    chunk_size = 256 * 1024
    chunks = []
    start = 0
    while start < len(raw):
        end = min(start + chunk_size, len(raw))
        # Align to newline boundary
        if end < len(raw):
            nl = raw.rfind(b"\n", start, end)
            if nl > start:
                end = nl + 1
        chunks.append(raw[start:end])
        start = end
    return chunks, line_count


def tcp_worker(args):
    """Send NDJSON chunks over persistent TCP socket."""
    worker_id, chunks, host, port, duration, warmup = args

    sent_bytes = 0
    sent_lines = 0
    errors = 0

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        sock.settimeout(10)
        sock.connect((host, port))
    except Exception as e:
        return {"worker_id": worker_id, "sent_lines": 0, "sent_bytes": 0,
                "errors": 1, "error_msg": str(e)}

    t_start = time.monotonic()
    t_warmup_end = t_start + warmup
    t_end = t_warmup_end + duration

    chunk_idx = 0
    n_chunks = len(chunks)

    while True:
        now = time.monotonic()
        if now >= t_end:
            break

        chunk = chunks[chunk_idx % n_chunks]
        chunk_idx += 1

        try:
            sock.sendall(chunk)
            if now >= t_warmup_end:
                sent_bytes += len(chunk)
                sent_lines += chunk.count(b"\n")
        except Exception:
            if now >= t_warmup_end:
                errors += 1
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

    return {"worker_id": worker_id, "sent_lines": sent_lines,
            "sent_bytes": sent_bytes, "errors": errors}


def main():
    parser = argparse.ArgumentParser(description="CLIF Final E2E Benchmark")
    parser.add_argument("--duration", type=int, default=60, help="Measurement duration (s)")
    parser.add_argument("--warmup", type=int, default=5, help="Warmup (s)")
    parser.add_argument("--workers", type=int, default=6, help="Parallel TCP connections")
    parser.add_argument("--host", default="localhost", help="Vector TCP host")
    parser.add_argument("--port", type=int, default=9514, help="Vector TCP port")
    parser.add_argument("--wait", type=int, default=30, help="Post-test CH drain wait (s)")
    args = parser.parse_args()

    print("=" * 70)
    print("  CLIF FINAL PRODUCTION E2E BENCHMARK")
    print("  Vector → Redpanda → Consumer → ClickHouse (full production path)")
    print("=" * 70)
    print(f"  Duration:   {args.duration}s + {args.warmup}s warmup")
    print(f"  Workers:    {args.workers} persistent TCP connections")
    print(f"  Target:     tcp://{args.host}:{args.port}")
    print(f"  Pipeline:   acknowledgements=true, wait_for_async_insert=1")
    print(f"              acks=-1, idempotent, drain-before-commit")
    print("-" * 70)

    # ── Load payload ─────────────────────────────────────────────────────
    payload_path = PAYLOAD_PATH if PAYLOAD_PATH.exists() else ALT_PAYLOAD
    if not payload_path.exists():
        print(f"  ERROR: No payload file found at {PAYLOAD_PATH} or {ALT_PAYLOAD}")
        sys.exit(1)

    chunks, total_lines = load_payload(payload_path)
    total_mb = sum(len(c) for c in chunks) / 1024 / 1024
    print(f"  Loaded: {total_lines:,} events, {total_mb:.1f} MB, {len(chunks)} chunks")

    # ── Test Vector TCP connectivity ─────────────────────────────────────
    print(f"\n  Testing Vector TCP at {args.host}:{args.port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((args.host, args.port))
        s.sendall(b'{"message":"benchmark-healthcheck","source_type":"test"}\n')
        time.sleep(0.1)
        s.close()
        print("  OK — Vector TCP reachable")
    except Exception as e:
        print(f"  FAIL — {e}")
        sys.exit(1)

    # ── ClickHouse baseline ──────────────────────────────────────────────
    print("\n  ClickHouse baseline counts:")
    ch_before = get_ch_counts()
    for t, c in sorted(ch_before.items()):
        print(f"    {t:25s}  {c:>12,}" if isinstance(c, int) else f"    {t:25s}  {c}")

    # ── Distribute chunks to workers ─────────────────────────────────────
    worker_chunks = [[] for _ in range(args.workers)]
    for i, chunk in enumerate(chunks):
        worker_chunks[i % args.workers].append(chunk)

    # ── Run benchmark ────────────────────────────────────────────────────
    print(f"\n  Starting {args.workers} TCP workers...")
    print(f"  Warmup: {args.warmup}s | Measuring: {args.duration}s")
    print()

    worker_args = [
        (i, worker_chunks[i], args.host, args.port, args.duration, args.warmup)
        for i in range(args.workers)
    ]

    t_wall_start = time.monotonic()

    with multiprocessing.Pool(processes=args.workers) as pool:
        results = pool.map(tcp_worker, worker_args)

    t_wall_end = time.monotonic()
    wall_time = t_wall_end - t_wall_start
    measure_time = wall_time - args.warmup

    # ── Aggregate results ────────────────────────────────────────────────
    total_sent = sum(r["sent_lines"] for r in results)
    total_bytes = sum(r["sent_bytes"] for r in results)
    total_errors = sum(r["errors"] for r in results)

    eps = total_sent / measure_time if measure_time > 0 else 0
    mbps = total_bytes / measure_time / 1024 / 1024 if measure_time > 0 else 0

    # Per-worker breakdown
    print("  Per-worker results:")
    print(f"    {'Worker':>8}  {'Events':>12}  {'MB':>10}  {'Errors':>8}")
    print("    " + "-" * 44)
    for r in results:
        wid = r["worker_id"]
        wevt = r["sent_lines"]
        wmb = r["sent_bytes"] / 1024 / 1024
        werr = r["errors"]
        print(f"    {wid:>8}  {wevt:>12,}  {wmb:>10.1f}  {werr:>8}")

    print()
    print("=" * 70)
    print("  THROUGHPUT RESULTS")
    print("=" * 70)
    print(f"  Total events sent:     {total_sent:>15,}")
    print(f"  Total data sent:       {total_bytes / 1024 / 1024:>15.1f} MB")
    print(f"  Wall time:             {wall_time:>15.1f} s")
    print(f"  Measure time:          {measure_time:>15.1f} s")
    print(f"  Errors:                {total_errors:>15,}")
    print(f"  ─────────────────────────────────────────────")
    print(f"  EPS (events/sec):      {eps:>15,.0f}")
    print(f"  MB/s:                  {mbps:>15.1f}")
    print(f"  Per-core (6 cores):    {eps / 6:>15,.0f} EPS/core")
    print()

    # ── Wait for ClickHouse drain ────────────────────────────────────────
    print(f"  Waiting {args.wait}s for Redpanda → Consumer → ClickHouse drain...")
    time.sleep(args.wait)

    # ── ClickHouse verification ──────────────────────────────────────────
    print("\n  ClickHouse E2E Delivery Verification:")
    print(f"    {'Table':25s}  {'Before':>12}  {'After':>12}  {'New':>12}")
    print("    " + "-" * 65)
    ch_after = get_ch_counts()
    total_new = 0
    for t in TABLES:
        before = ch_before.get(t, 0)
        after = ch_after.get(t, 0)
        if isinstance(before, int) and isinstance(after, int):
            new = after - before
            total_new += new
            mark = "+" if new > 0 else " "
            print(f"  {mark} {t:25s}  {before:>12,}  {after:>12,}  {new:>12,}")
        else:
            print(f"  ? {t:25s}  {str(before):>12}  {str(after):>12}  {'?':>12}")
    print("    " + "-" * 65)
    print(f"    TOTAL IN CLICKHOUSE:                             {total_new:>12,}")

    if total_sent > 0:
        delivery_pct = total_new / total_sent * 100
        print(f"\n  Delivery Rate: {total_new:,} / {total_sent:,} = {delivery_pct:.1f}%")

        # Note: delivery rate may exceed 100% (events still draining)
        # or be < 100% (consumer still processing). Both are normal.
        if total_new == 0:
            print("  WARNING: 0 events in ClickHouse — consumer may be stopped or lagging")

    # ── Consumer stats ───────────────────────────────────────────────────
    print("\n  Consumer logs (last stats line):")
    import subprocess
    try:
        res = subprocess.run(
            ["docker", "logs", "clif-consumer", "--tail", "5"],
            capture_output=True, text=True, timeout=10
        )
        for line in (res.stdout + res.stderr).strip().split("\n"):
            if "Stats" in line or "rate=" in line:
                print(f"    {line.strip()}")
    except Exception:
        print("    (could not read consumer logs)")

    print()
    print("=" * 70)
    print(f"  FINAL: {eps:,.0f} total EPS | {eps / 6:,.0f} per-core (6C)")
    print(f"         Full production path: Vector→Redpanda→Consumer→ClickHouse")
    print(f"         {total_new:,} events verified in ClickHouse")
    print("=" * 70)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
