#!/usr/bin/env python3
"""
CLIF Pipeline v2 Benchmark — Pre-generated payload for accurate throughput measurement.
Eliminates Python JSON-generation overhead from the timing window.
"""

import socket
import time
import json
import random
import sys
import threading
import os
from datetime import datetime, timezone

# ── Configuration ────────────────────────────────────────────────────────────
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 9514
TOTAL_EVENTS = 500_000
BATCH_SIZE = 5000  # Events per TCP send
NUM_CONNECTIONS = 6  # Match Vector thread count
VECTOR_CPUS = 6
PAYLOAD_FILE = "benchmark_payload.ndjson"

# ── Event Templates ──────────────────────────────────────────────────────────
def random_ip():
    return f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def random_port():
    return random.randint(1024, 65535)

SECURITY_MESSAGES = [
    "Failed password for invalid user admin from {ip} port {port} ssh2",
    "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}",
    "Invalid user root from {ip} port {port}",
    "Accepted publickey for deploy from {ip} port {port} ssh2: RSA SHA256:abc",
    "Malware detected: trojan.generic in /tmp/payload.bin from {ip}",
    "Port scan detected from {ip}: 1000 ports scanned in 5 seconds",
    "Brute force attack: 50 failed logins from {ip} in 60 seconds",
    "Account locked after 5 failed attempts for user admin from {ip}",
    "SYN flood detected from {ip} targeting port 80",
    "DNS tunnel activity from {ip} to malware.evil.com",
    "Lateral movement detected from {ip} to 10.0.2.100",
    "Firewall DROP: SRC={ip} DST=10.0.1.1 PROTO=TCP DPT=22",
]

PROCESS_TEMPLATES = [
    {"message": "exec /usr/bin/python3 pid={pid} uid=1000 cwd=/app", "pid": True},
    {"message": "Process terminated: pid={pid} exit_code=0 binary=/usr/local/bin/node", "pid": True},
    {"message": "cron[{pid}]: (root) CMD (/usr/local/bin/backup.sh)", "pid": True},
    {"message": "systemd[1]: Started session for user deploy pid={pid}", "pid": True},
]

NETWORK_TEMPLATES = [
    "TCP connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
    "UDP packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port} bytes={bytes}",
    "iptables ACCEPT: SRC={src_ip} DST={dst_ip} PROTO=TCP SPT={src_port} DPT={dst_port}",
    "Connection closed: {src_ip}:{src_port} -> {dst_ip}:{dst_port} duration={dur}ms",
]

RAW_MESSAGES = [
    "INFO Application started successfully on port 8080",
    "WARNING Disk usage at 85%% on /var/log",
    "INFO Request processed in {dur}ms status=200 path=/api/health",
    "INFO Cache hit ratio: 94.2%% (1234/1310)",
    "WARNING Connection pool exhausted, waiting for connection",
    "INFO Deployment v2.3.1 completed in 45s",
    "INFO Background job: cleanup_stale_sessions duration={dur}ms",
]


def generate_event():
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    roll = random.random()

    if roll < 0.25:  # Security
        msg = random.choice(SECURITY_MESSAGES).format(ip=random_ip(), port=random_port())
        return {"timestamp": ts, "level": random.choice(["WARNING","ERROR","CRITICAL"]),
                "source": random.choice(["sshd","pam_unix","auditd","snort"]),
                "message": msg, "hostname": f"srv-{random.randint(1,50):02d}"}

    elif roll < 0.45:  # Process
        pid = random.randint(1000, 65535)
        tpl = random.choice(PROCESS_TEMPLATES)
        return {"timestamp": ts, "level": "INFO",
                "source": random.choice(["systemd","cron","kernel"]),
                "message": tpl["message"].format(pid=pid),
                "hostname": f"srv-{random.randint(1,50):02d}",
                "pid": pid, "ppid": random.randint(1,999), "uid": random.choice([0,1000])}

    elif roll < 0.65:  # Network
        msg = random.choice(NETWORK_TEMPLATES).format(
            src_ip=random_ip(), src_port=random_port(),
            dst_ip=random_ip(), dst_port=random.choice([22,80,443,3306,8080]),
            bytes=random.randint(64,1048576), dur=random.randint(1,30000))
        return {"timestamp": ts, "level": "INFO",
                "source": random.choice(["iptables","conntrack"]),
                "message": msg, "hostname": f"fw-{random.randint(1,5):02d}",
                "src_ip": random_ip(), "dst_ip": random_ip(),
                "src_port": random_port(), "dst_port": random.choice([22,80,443]),
                "protocol": random.choice(["TCP","UDP"])}

    else:  # Raw
        msg = random.choice(RAW_MESSAGES).format(ip=random_ip(), dur=random.randint(1,5000))
        return {"timestamp": ts, "level": random.choice(["INFO","WARNING"]),
                "source": random.choice(["app","nginx","postgres","redis"]),
                "message": msg, "hostname": f"app-{random.randint(1,20):02d}"}


def pre_generate_payload():
    """Pre-generate the entire payload to disk."""
    print(f"[1/5] Pre-generating {TOTAL_EVENTS:,} events to {PAYLOAD_FILE}...")
    start = time.perf_counter()
    with open(PAYLOAD_FILE, "w", encoding="utf-8") as f:
        for i in range(TOTAL_EVENTS):
            event = generate_event()
            f.write(json.dumps(event, separators=(",", ":")) + "\n")
            if (i + 1) % 100_000 == 0:
                print(f"  Generated {i+1:,} events...")

    elapsed = time.perf_counter() - start
    size_mb = os.path.getsize(PAYLOAD_FILE) / (1024 * 1024)
    print(f"  Done: {size_mb:.1f} MB in {elapsed:.1f}s ({TOTAL_EVENTS/elapsed:,.0f} events/s gen rate)")
    return size_mb


def load_payload_chunks():
    """Load payload and split into chunks for parallel sending."""
    print(f"[2/5] Loading payload into memory...")
    with open(PAYLOAD_FILE, "rb") as f:
        data = f.read()

    lines = data.split(b"\n")
    lines = [l for l in lines if l.strip()]  # Remove empty lines
    actual_events = len(lines)
    print(f"  Loaded {actual_events:,} events ({len(data) / (1024*1024):.1f} MB)")

    # Split into per-connection chunks
    chunk_size = actual_events // NUM_CONNECTIONS
    chunks = []
    for i in range(NUM_CONNECTIONS):
        start = i * chunk_size
        end = start + chunk_size if i < NUM_CONNECTIONS - 1 else actual_events
        chunk_lines = lines[start:end]
        chunks.append(b"\n".join(chunk_lines) + b"\n")

    return chunks, actual_events


def send_worker(thread_id, payload_bytes, results):
    """Send pre-generated payload over TCP as fast as possible."""
    sent_bytes = 0
    errors = 0
    total_bytes = len(payload_bytes)

    # Split into send chunks (64KB TCP writes)
    SEND_CHUNK = 65536
    start = time.perf_counter()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        sock.settimeout(60)
        sock.connect((TARGET_HOST, TARGET_PORT))

        offset = 0
        while offset < total_bytes:
            end = min(offset + SEND_CHUNK, total_bytes)
            sock.sendall(payload_bytes[offset:end])
            sent_bytes += (end - offset)
            offset = end

        sock.shutdown(socket.SHUT_WR)
        time.sleep(0.5)
        sock.close()

    except Exception as e:
        errors += 1
        print(f"  [Thread {thread_id}] Error: {e}")

    elapsed = time.perf_counter() - start
    results[thread_id] = {
        "bytes": sent_bytes,
        "elapsed": elapsed,
        "errors": errors,
        "mbps": (sent_bytes / (1024*1024)) / elapsed if elapsed > 0 else 0,
    }


def main():
    print("=" * 70)
    print("CLIF Pipeline v2 — Pre-Generated Payload Benchmark")
    print("=" * 70)
    print(f"  Target:        {TARGET_HOST}:{TARGET_PORT} (TCP NDJSON)")
    print(f"  Total Events:  {TOTAL_EVENTS:,}")
    print(f"  Connections:   {NUM_CONNECTIONS}")
    print(f"  Vector CPUs:   {VECTOR_CPUS}")
    print()

    # Phase 1: Generate payload
    size_mb = pre_generate_payload()

    # Phase 2: Load into memory
    chunks, actual_events = load_payload_chunks()

    # Phase 3: Pre-warm
    print(f"[3/5] Pre-warming Vector pipeline...")
    warmup = chunks[0][:4096]  # Small warmup
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((TARGET_HOST, TARGET_PORT))
        sock.sendall(warmup)
        sock.close()
    except:
        pass
    time.sleep(2)

    # Phase 4: Benchmark
    print(f"[4/5] Sending {actual_events:,} events across {NUM_CONNECTIONS} connections...")
    results = {}
    threads = []
    wall_start = time.perf_counter()

    for i in range(NUM_CONNECTIONS):
        t = threading.Thread(target=send_worker, args=(i, chunks[i], results))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    wall_elapsed = time.perf_counter() - wall_start

    # Calculate results
    total_bytes = sum(r["bytes"] for r in results.values())
    total_errors = sum(r["errors"] for r in results.values())
    total_mbps = (total_bytes / (1024*1024)) / wall_elapsed if wall_elapsed > 0 else 0
    eps = actual_events / wall_elapsed if wall_elapsed > 0 else 0
    eps_per_core = eps / VECTOR_CPUS

    print(f"[5/5] Waiting for ClickHouse flush (8s)...")
    time.sleep(8)

    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"  Events Sent:       {actual_events:,}")
    print(f"  Payload Size:      {size_mb:.1f} MB")
    print(f"  Wall Time:         {wall_elapsed:.2f}s")
    print(f"  Throughput:        {total_mbps:.1f} MB/s")
    print(f"  Total EPS:         {eps:,.0f}")
    print(f"  Per-Core EPS:      {eps_per_core:,.0f}  (Vector on {VECTOR_CPUS} CPUs)")
    print(f"  Send Errors:       {total_errors}")
    print()

    print("Per-Thread Breakdown:")
    for tid, r in sorted(results.items()):
        print(f"  Thread {tid}: {r['bytes']/(1024*1024):.1f} MB in {r['elapsed']:.2f}s = {r['mbps']:.1f} MB/s")
    print()

    # Check ClickHouse counts
    print("ClickHouse Row Counts (approximate — async inserts may still be flushing):")
    try:
        import subprocess
        cmd = [
            "docker", "exec", "clif-clickhouse01", "clickhouse-client",
            "--user", "clif_admin", "--password", "Cl1f_Ch@ngeM3_2026!",
            "-d", "clif_logs",
            "-q", "SELECT 'raw_logs' AS tbl, count() AS cnt FROM raw_logs UNION ALL SELECT 'security_events', count() FROM security_events UNION ALL SELECT 'process_events', count() FROM process_events UNION ALL SELECT 'network_events', count() FROM network_events FORMAT TSV"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        total_ch = 0
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                parts = line.split("\t")
                if len(parts) == 2:
                    tbl, cnt = parts
                    cnt = int(cnt)
                    total_ch += cnt
                    print(f"  {tbl}: {cnt:,}")
        print(f"  TOTAL in CH: {total_ch:,}")
        if total_ch > 0:
            delivery_pct = (total_ch / actual_events) * 100
            print(f"  Delivery Rate: {delivery_pct:.1f}%")
    except Exception as e:
        print(f"  Could not query ClickHouse: {e}")

    print()
    print("=" * 70)


if __name__ == "__main__":
    main()
