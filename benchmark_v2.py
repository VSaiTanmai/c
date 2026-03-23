#!/usr/bin/env python3
"""
CLIF Pipeline v2 Benchmark — Direct-to-ClickHouse Architecture
Measures per-core EPS for TCP NDJSON ingestion → Vector → ClickHouse direct sinks.
"""

import socket
import time
import json
import random
import string
import sys
import threading
from datetime import datetime, timezone

# ── Configuration ────────────────────────────────────────────────────────────
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 9514
TOTAL_EVENTS = 200_000
BATCH_SIZE = 2000
NUM_CONNECTIONS = 4  # Parallel TCP connections
VECTOR_CPUS = 6  # CPUs allocated to Vector in docker-compose

# ── Event Templates ──────────────────────────────────────────────────────────

SECURITY_MESSAGES = [
    "Failed password for invalid user admin from {ip} port 22 ssh2",
    "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}",
    "Invalid user root from {ip} port {port}",
    "Accepted publickey for deploy from {ip} port {port} ssh2: RSA SHA256:abc123",
    "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user=nobody",
    "Malware detected: trojan.generic in /tmp/payload.bin from {ip}",
    "Port scan detected from {ip}: 1000 ports scanned in 5 seconds",
    "Brute force attack detected: 50 failed logins from {ip} in 60 seconds",
    "Account locked after 5 failed attempts for user admin from {ip}",
    "session opened for user root by (uid=0) from {ip}",
    "SYN flood detected from {ip} targeting port 80",
    "DNS tunnel activity detected from {ip} to suspicious domain malware.evil.com",
]

PROCESS_MESSAGES = [
    "Process started: pid={pid} ppid=1 uid=0 binary=/usr/sbin/sshd args=-D",
    "exec /usr/bin/python3 pid={pid} uid=1000 cwd=/app",
    "Process terminated: pid={pid} exit_code=0 binary=/usr/local/bin/node",
    "cron[{pid}]: (root) CMD (/usr/local/bin/backup.sh)",
    "systemd[1]: Started {pid} session service for user deploy",
    "kernel: [12345.678] audit: type=1400 audit(1234567890.123:456): apparmor pid={pid}",
]

NETWORK_MESSAGES = [
    "TCP connection established: {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
    "UDP packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port} bytes={bytes}",
    "Firewall ACCEPT: IN=eth0 OUT= SRC={src_ip} DST={dst_ip} PROTO=TCP SPT={src_port} DPT={dst_port}",
    "Connection closed: {src_ip}:{src_port} -> {dst_ip}:{dst_port} duration={duration}ms bytes_sent={bytes}",
    "DNS query: {src_ip} -> {dst_ip} A record api.example.com",
]

RAW_MESSAGES = [
    "INFO Application started successfully on port 8080",
    "WARNING Disk usage at 85% on /var/log",
    "INFO Request processed in {duration}ms status=200 path=/api/health",
    "INFO Cache hit ratio: 94.2% (1234/1310)",
    "WARNING Connection pool exhausted, waiting for available connection",
    "INFO Deployment v2.3.1 completed successfully in 45s",
    "INFO Background job completed: cleanup_stale_sessions duration={duration}ms",
    "INFO User login: user_id=deploy source=api ip={ip}",
]


def random_ip():
    return f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def random_port():
    return random.randint(1024, 65535)


def generate_event():
    """Generate a random realistic log event."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    roll = random.random()

    if roll < 0.25:  # 25% security
        msg_tpl = random.choice(SECURITY_MESSAGES)
        msg = msg_tpl.format(
            ip=random_ip(),
            port=random_port(),
            pid=random.randint(1000, 65535),
        )
        return {
            "timestamp": ts,
            "level": random.choice(["WARNING", "ERROR", "CRITICAL"]),
            "source": random.choice(["sshd", "pam_unix", "auditd", "snort", "suricata"]),
            "message": msg,
            "hostname": f"srv-{random.randint(1, 50):02d}",
        }
    elif roll < 0.45:  # 20% process
        msg_tpl = random.choice(PROCESS_MESSAGES)
        pid = random.randint(1000, 65535)
        return {
            "timestamp": ts,
            "level": "INFO",
            "source": random.choice(["systemd", "cron", "kernel", "auditd"]),
            "message": msg_tpl.format(pid=pid),
            "hostname": f"srv-{random.randint(1, 50):02d}",
            "pid": pid,
            "ppid": random.randint(1, 999),
            "uid": random.choice([0, 1000, 1001, 65534]),
        }
    elif roll < 0.65:  # 20% network
        msg_tpl = random.choice(NETWORK_MESSAGES)
        return {
            "timestamp": ts,
            "level": "INFO",
            "source": random.choice(["iptables", "conntrack", "tcpdump"]),
            "message": msg_tpl.format(
                src_ip=random_ip(),
                src_port=random_port(),
                dst_ip=random_ip(),
                dst_port=random.choice([22, 80, 443, 3306, 5432, 6379, 8080, 8443]),
                bytes=random.randint(64, 1048576),
                duration=random.randint(1, 30000),
            ),
            "hostname": f"fw-{random.randint(1, 5):02d}",
            "src_ip": random_ip(),
            "dst_ip": random_ip(),
            "src_port": random_port(),
            "dst_port": random.choice([22, 80, 443, 3306, 5432]),
            "protocol": random.choice(["TCP", "UDP"]),
        }
    else:  # 35% raw
        msg_tpl = random.choice(RAW_MESSAGES)
        return {
            "timestamp": ts,
            "level": random.choice(["INFO", "WARNING"]),
            "source": random.choice(["app", "nginx", "postgres", "redis", "api-gateway"]),
            "message": msg_tpl.format(
                ip=random_ip(),
                duration=random.randint(1, 5000),
            ),
            "hostname": f"app-{random.randint(1, 20):02d}",
        }


def generate_batch(size):
    """Generate a batch of newline-delimited JSON events."""
    lines = []
    for _ in range(size):
        event = generate_event()
        lines.append(json.dumps(event, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def send_batch(host, port, data_bytes):
    """Send a batch of events over a single TCP reconnection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    sock.settimeout(30)
    sock.connect((host, port))
    sock.sendall(data_bytes)
    sock.close()


def worker(thread_id, events_per_thread, results):
    """Worker thread: generate and send events in batches."""
    sent = 0
    errors = 0
    start = time.perf_counter()

    while sent < events_per_thread:
        batch_sz = min(BATCH_SIZE, events_per_thread - sent)
        batch_data = generate_batch(batch_sz).encode("utf-8")
        try:
            send_batch(TARGET_HOST, TARGET_PORT, batch_data)
            sent += batch_sz
        except Exception as e:
            errors += 1
            if errors > 20:
                print(f"  [Thread {thread_id}] Too many errors, stopping: {e}")
                break
            time.sleep(0.1)

    elapsed = time.perf_counter() - start
    results[thread_id] = {"sent": sent, "elapsed": elapsed, "errors": errors}


def main():
    print("=" * 70)
    print("CLIF Pipeline v2 Benchmark — Direct-to-ClickHouse")
    print("=" * 70)
    print(f"  Target:        {TARGET_HOST}:{TARGET_PORT} (TCP NDJSON)")
    print(f"  Total Events:  {TOTAL_EVENTS:,}")
    print(f"  Connections:   {NUM_CONNECTIONS}")
    print(f"  Batch Size:    {BATCH_SIZE:,}")
    print(f"  Vector CPUs:   {VECTOR_CPUS}")
    print()

    # Pre-warm: send a small batch to ensure connection is established
    print("[1/4] Pre-warming connection...")
    warmup = generate_batch(100).encode("utf-8")
    send_batch(TARGET_HOST, TARGET_PORT, warmup)
    time.sleep(2)

    # Run benchmark
    print(f"[2/4] Sending {TOTAL_EVENTS:,} events across {NUM_CONNECTIONS} threads...")
    events_per_thread = TOTAL_EVENTS // NUM_CONNECTIONS
    results = {}
    threads = []

    wall_start = time.perf_counter()

    for i in range(NUM_CONNECTIONS):
        t = threading.Thread(target=worker, args=(i, events_per_thread, results))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    wall_elapsed = time.perf_counter() - wall_start

    # Calculate results
    total_sent = sum(r["sent"] for r in results.values())
    total_errors = sum(r["errors"] for r in results.values())
    eps = total_sent / wall_elapsed if wall_elapsed > 0 else 0
    eps_per_core = eps / VECTOR_CPUS

    print(f"[3/4] Waiting for ClickHouse flush (5s)...")
    time.sleep(5)

    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"  Events Sent:      {total_sent:,}")
    print(f"  Wall Time:        {wall_elapsed:.2f}s")
    print(f"  Total EPS:        {eps:,.0f}")
    print(f"  Per-Core EPS:     {eps_per_core:,.0f}  (Vector on {VECTOR_CPUS} CPUs)")
    print(f"  Send Errors:      {total_errors}")
    print()

    # Per-thread breakdown
    print("Per-Thread Breakdown:")
    for tid, r in sorted(results.items()):
        t_eps = r["sent"] / r["elapsed"] if r["elapsed"] > 0 else 0
        print(f"  Thread {tid}: {r['sent']:,} events in {r['elapsed']:.2f}s = {t_eps:,.0f} EPS")
    print()

    print("[4/4] Done.")


if __name__ == "__main__":
    main()
