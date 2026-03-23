#!/usr/bin/env python3
"""
CLIF Vector End-to-End EPS Test
================================
Sends realistic logs through Vector's input ports (TCP NDJSON + Syslog)
instead of bypassing Vector and writing directly to Redpanda.

Full pipeline path:
  This Script → Vector (TCP:9514 / Syslog:1514)
    → mega_transform (parse + classify + normalize)
    → route_by_type
    → Redpanda (4 topics)
    → Go Consumer (batch insert)
    → ClickHouse

Log types generated:
  - Syslog RFC3164 (auth failures, sudo, connections) → port 1514 TCP
  - NDJSON structured (security, process, network, raw) → port 9514 TCP

Usage:
    python run_vector_eps_test.py --duration 120
    python run_vector_eps_test.py --duration 120 --vector-host localhost
    python run_vector_eps_test.py --duration 60 --workers 8
"""

from __future__ import annotations

import argparse
import random
import signal
import socket
import sys
import time
from datetime import datetime, timezone
from threading import Event, Thread

try:
    import orjson
    def _fast_dumps(obj: dict) -> bytes:
        return orjson.dumps(obj) + b"\n"
except ImportError:
    import json
    def _fast_dumps(obj: dict) -> bytes:
        return (json.dumps(obj) + "\n").encode()

# ── CLI ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="CLIF Vector End-to-End EPS Test")
parser.add_argument("--vector-host", default="localhost", help="Vector host (default: localhost)")
parser.add_argument("--tcp-port", type=int, default=9514, help="Vector TCP NDJSON port (default: 9514)")
parser.add_argument("--syslog-port", type=int, default=1514, help="Vector Syslog TCP port (default: 1514)")
parser.add_argument("--duration", type=int, default=120, help="Test duration in seconds (default: 120)")
parser.add_argument("--workers", type=int, default=6, help="Number of TCP sender threads (default: 6)")
parser.add_argument("--syslog-workers", type=int, default=2, help="Number of Syslog sender threads (default: 2)")
args = parser.parse_args()

VECTOR_HOST = args.vector_host
TCP_PORT = args.tcp_port
SYSLOG_PORT = args.syslog_port
DURATION = args.duration
WORKERS = args.workers
SYSLOG_WORKERS = args.syslog_workers

# ── Graceful shutdown ────────────────────────────────────────────────────────
_stop = Event()

def _sigint(sig, frame):
    print("\n[!] Ctrl+C — stopping…")
    _stop.set()

signal.signal(signal.SIGINT, _sigint)

# ── Pre-computed data pools ─────────────────────────────────────────────────
_IPS = tuple(f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
             for _ in range(500))
_HOSTS = tuple(f"WS-{i:04d}" for i in range(20))
_USERS = tuple(f"user_{i:03d}" for i in range(50))
_BINARIES = (
    "/usr/bin/sshd", "/usr/bin/sudo", "/usr/sbin/cron", "/usr/bin/bash",
    "/usr/bin/python3", "/usr/sbin/nginx", "/usr/bin/curl", "/usr/bin/wget",
    "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\powershell.exe",
    "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\rundll32.exe",
)
_PORTS = (22, 80, 443, 8080, 53, 3306, 5432, 6379, 9092, 445, 3389, 8443)
_PROTOS = ("TCP", "TCP", "TCP", "UDP", "UDP")
_DIRS = ("inbound", "outbound")
_GEOS = ("US", "US", "US", "CN", "RU", "DE", "GB", "IN", "BR", "")
_SOURCES = ("sshd", "auditd", "kernel", "sudo", "nginx", "sysmon", "firewall")
_DNS = tuple(f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(4,10)))}.{'com' if random.random() < 0.5 else 'net'}"
             for _ in range(100))
_UTC = timezone.utc

# ── Timestamp helpers ───────────────────────────────────────────────────────
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

def _now_iso() -> str:
    return datetime.now(_UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def _now_syslog() -> str:
    """RFC 3164 timestamp: Mar 10 14:23:01"""
    n = datetime.now(_UTC)
    return f"{_MONTHS[n.month-1]} {n.day:2d} {n.strftime('%H:%M:%S')}"


# ══════════════════════════════════════════════════════════════════════════════
#  REALISTIC LOG GENERATORS
# ══════════════════════════════════════════════════════════════════════════════

# ── Syslog RFC 3164 messages (sent to port 1514) ────────────────────────────
# These trigger Vector's syslog source → mega_transform → classification

_SYSLOG_TEMPLATES = (
    # Auth failures → security events
    "<34>{ts} {host} sshd[{pid}]: Failed password for {user} from {ip} port {sport} ssh2",
    "<34>{ts} {host} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {sport} ssh2",
    "<38>{ts} {host} sshd[{pid}]: Accepted publickey for {user} from {ip} port {sport} ssh2",
    "<38>{ts} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {sport} ssh2",
    "<34>{ts} {host} sshd[{pid}]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}",
    # Sudo → security events
    "<85>{ts} {host} sudo[{pid}]:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update",
    "<85>{ts} {host} sudo[{pid}]:   {user} : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/iptables -L",
    # Firewall → security events
    "<134>{ts} {host} kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC={ip} DST={ip2} LEN=52 TTL=128 DF PROTO=TCP SPT={sport} DPT={dport} WINDOW=65535 RES=0x00 SYN",
    "<134>{ts} {host} iptables[{pid}]: BLOCKED connection from {ip} to {ip2}:{dport} proto TCP",
    # Malware / threat indicators
    "<33>{ts} {host} edr-agent[{pid}]: malware detected: trojan.gen.2 PID={pid2} binary=/tmp/.hidden/payload user={user}",
    "<33>{ts} {host} clamd[{pid}]: /home/{user}/Downloads/invoice.pdf.exe: Win.Trojan.Agent-12345 FOUND",
    # Network events (process+connection style)
    "<134>{ts} {host} auditd[{pid}]: type=SYSCALL arch=c000003e syscall=42 success=yes exit=0 pid={pid2} comm=\"curl\" exe=\"/usr/bin/curl\"",
    # Brute force / account lockout
    "<33>{ts} {host} sshd[{pid}]: error: maximum authentication attempts exceeded for {user} from {ip} port {sport} ssh2",
    "<33>{ts} {host} pam_tally2[{pid}]: account locked: user {user} exceeded max retries from {ip}",
    # Port scans
    "<33>{ts} {host} snort[{pid}]: [1:2001219:20] ET SCAN Potential SSH Scan {ip} -> {ip2}",
    # Exfiltration indicators
    "<33>{ts} {host} dlp-agent[{pid}]: large upload detected: {user}@{host} → {ip}:{dport} bytes=104857600 duration=45s",
    "<33>{ts} {host} ids[{pid}]: data leak: unusual transfer volume from {ip} to {ip2} port {dport}",
    # DNS tunnel
    "<33>{ts} {host} named[{pid}]: dns tunnel suspected: queries={dns} from {ip} query_rate=500/s",
    # Lateral movement
    "<33>{ts} {host} winlogbeat[{pid}]: lateral movement: RDP session from {ip} to {ip2} user={user}",
    # Normal syslog (→ raw_logs)
    "<30>{ts} {host} cron[{pid}]: ({user}) CMD (/usr/local/bin/backup.sh)",
    "<30>{ts} {host} systemd[1]: Started Daily apt download activities.",
    "<30>{ts} {host} systemd[1]: docker.service: Scheduled restart job, restart counter is {pid}.",
    "<30>{ts} {host} ntpd[{pid}]: kernel reports TIME_ERROR: 0x2041",
    "<30>{ts} {host} rsyslogd[{pid}]: action 'action-3-builtin:omjournal' resumed",
)

def _gen_syslog() -> bytes:
    """Generate a single RFC 3164 syslog message."""
    tmpl = random.choice(_SYSLOG_TEMPLATES)
    msg = tmpl.format(
        ts=_now_syslog(),
        host=random.choice(_HOSTS),
        user=random.choice(_USERS),
        ip=random.choice(_IPS),
        ip2=random.choice(_IPS),
        pid=random.randint(100, 65535),
        pid2=random.randint(100, 65535),
        sport=random.randint(1024, 65535),
        dport=random.choice(_PORTS),
        dns=random.choice(_DNS),
    )
    return (msg + "\n").encode()


# ── NDJSON structured events (sent to port 9514) ────────────────────────────
# Vector's tcp_json source parses JSON, then mega_transform classifies.
# No clif_event_type pre-set: Vector must classify using regex/field checks.

def _gen_json_security() -> dict:
    """Security event WITHOUT clif_event_type — Vector must classify."""
    return {
        "timestamp": _now_iso(),
        "hostname": random.choice(_HOSTS),
        "source": random.choice(_SOURCES),
        "message": random.choice((
            f"Failed password for {random.choice(_USERS)} from {random.choice(_IPS)} port {random.randint(1024,65535)} ssh2",
            f"authentication failure: user={random.choice(_USERS)} rhost={random.choice(_IPS)}",
            f"Accepted publickey for {random.choice(_USERS)} from {random.choice(_IPS)} port {random.randint(1024,65535)}",
            f"malware detected: trojan variant on host {random.choice(_HOSTS)} pid={random.randint(100,65535)}",
            f"port scan detected from {random.choice(_IPS)} targeting 10.0.0.0/8 ports 22,445,3389",
            f"brute force attempt: 50 failed logins for {random.choice(_USERS)} from {random.choice(_IPS)}",
            f"reverse shell detected: {random.choice(_IPS)} → {random.choice(_IPS)}:4444",
            f"exfiltration alert: large upload {random.randint(100,999)}MB from {random.choice(_HOSTS)} to {random.choice(_IPS)}",
            f"dns tunnel detected: high-frequency queries to {random.choice(_DNS)} from {random.choice(_IPS)}",
            f"lateral movement: SMB session {random.choice(_IPS)} → {random.choice(_IPS)} user={random.choice(_USERS)}",
            f"firewall DROP IN=eth0 SRC={random.choice(_IPS)} DST={random.choice(_IPS)} PROTO=TCP DPT={random.choice(_PORTS)}",
            f"access denied for {random.choice(_USERS)} to /etc/shadow from {random.choice(_IPS)}",
        )),
        "level": random.choice(("ERROR", "WARNING", "CRITICAL")),
    }

def _gen_json_process() -> dict:
    """Process event with pid/ppid — Vector classifies as process_events."""
    return {
        "timestamp": _now_iso(),
        "hostname": random.choice(_HOSTS),
        "pid": random.randint(1, 65535),
        "ppid": random.randint(1, 65535),
        "uid": random.randint(0, 65534),
        "gid": random.randint(0, 65534),
        "binary_path": random.choice(_BINARIES),
        "arguments": f"--config /etc/app.conf --user {random.choice(_USERS)}",
        "cwd": f"/home/{random.choice(_USERS)}",
        "exit_code": random.choice((0, 0, 0, 0, 1, 137, -1)),
        "syscall": random.choice(("execve", "fork", "clone", "NtCreateProcess")),
        "message": f"Process started: {random.choice(_BINARIES)} pid={random.randint(1,65535)}",
    }

def _gen_json_network() -> dict:
    """Network event with src_ip/dst_ip/ports — Vector classifies as network_events."""
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
        "message": f"Connection {random.choice(_IPS)}:{random.randint(1024,65535)} -> {random.choice(_IPS)}:{random.choice(_PORTS)}",
    }

def _gen_json_raw() -> dict:
    """Generic log that won't match security/process/network — goes to raw_logs."""
    return {
        "timestamp": _now_iso(),
        "hostname": random.choice(_HOSTS),
        "source": random.choice(("cron", "systemd", "nginx", "docker", "app-server")),
        "message": random.choice((
            f"Started scheduled task backup-daily on {random.choice(_HOSTS)}",
            f"Container {random.choice(_HOSTS)}-api restarted successfully",
            f"Disk usage at 67% on /dev/sda1 host={random.choice(_HOSTS)}",
            f"Service nginx reloaded configuration, PID unchanged",
            f"Certificate renewal completed for *.clif-siem.internal",
            f"NTP synchronized: offset=-0.003s stratum=2 server=time.internal",
            f"Logrotate: rotated /var/log/syslog, compressed 12 files",
        )),
        "level": random.choice(("INFO", "INFO", "INFO", "WARN")),
    }

# Weighted generator selection for NDJSON
_JSON_GENERATORS = (
    (_gen_json_security, 0.25),
    (_gen_json_process,  0.25),
    (_gen_json_network,  0.25),
    (_gen_json_raw,      0.25),
)
_JSON_GEN_FUNCS = tuple(g for g, _ in _JSON_GENERATORS)
_JSON_GEN_WEIGHTS = tuple(w for _, w in _JSON_GENERATORS)


# ══════════════════════════════════════════════════════════════════════════════
#  WORKER THREADS
# ══════════════════════════════════════════════════════════════════════════════

class WorkerStats:
    """Thread-safe stats counter."""
    def __init__(self):
        self.sent = 0
        self.errors = 0

_global_stats: list[WorkerStats] = []

def _tcp_ndjson_worker(worker_id: int, host: str, port: int):
    """Send NDJSON events to Vector's tcp_json source (port 9514)."""
    stats = WorkerStats()
    _global_stats.append(stats)

    sock = None
    batch_size = 200  # send N events per batch then flush
    buf = bytearray()
    _choices = random.choices

    while not _stop.is_set():
        # Connect/reconnect
        if sock is None:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
                sock.settimeout(5)
                sock.connect((host, port))
            except Exception as e:
                stats.errors += 1
                sock = None
                if not _stop.is_set():
                    time.sleep(1)
                continue

        # Generate batch
        buf.clear()
        gen_batch = _choices(_JSON_GEN_FUNCS, weights=_JSON_GEN_WEIGHTS, k=batch_size)
        for gen_fn in gen_batch:
            buf.extend(_fast_dumps(gen_fn()))

        try:
            sock.sendall(bytes(buf))
            stats.sent += batch_size
        except Exception:
            stats.errors += 1
            try:
                sock.close()
            except Exception:
                pass
            sock = None

    if sock:
        try:
            sock.close()
        except Exception:
            pass


def _syslog_worker(worker_id: int, host: str, port: int):
    """Send RFC 3164 syslog messages to Vector's syslog_tcp source (port 1514)."""
    stats = WorkerStats()
    _global_stats.append(stats)

    sock = None
    batch_size = 200

    while not _stop.is_set():
        if sock is None:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
                sock.settimeout(5)
                sock.connect((host, port))
            except Exception:
                stats.errors += 1
                sock = None
                if not _stop.is_set():
                    time.sleep(1)
                continue

        buf = bytearray()
        for _ in range(batch_size):
            buf.extend(_gen_syslog())

        try:
            sock.sendall(bytes(buf))
            stats.sent += batch_size
        except Exception:
            stats.errors += 1
            try:
                sock.close()
            except Exception:
                pass
            sock = None

    if sock:
        try:
            sock.close()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print(f"╔══════════════════════════════════════════════════════╗")
    print(f"║   CLIF Vector End-to-End EPS Test                   ║")
    print(f"╠══════════════════════════════════════════════════════╣")
    print(f"║ Vector Host : {VECTOR_HOST:<38} ║")
    print(f"║ TCP NDJSON  : port {TCP_PORT} ({WORKERS} workers){' '*(22-len(str(TCP_PORT))-len(str(WORKERS)))}║")
    print(f"║ Syslog TCP  : port {SYSLOG_PORT} ({SYSLOG_WORKERS} workers){' '*(22-len(str(SYSLOG_PORT))-len(str(SYSLOG_WORKERS)))}║")
    print(f"║ Duration    : {DURATION}s{' '*(37-len(str(DURATION)))}║")
    print(f"║ Pipeline    : Script→Vector→Redpanda→Consumer→CH    ║")
    print(f"╚══════════════════════════════════════════════════════╝")
    print()

    # Start worker threads
    threads: list[Thread] = []

    for i in range(WORKERS):
        t = Thread(target=_tcp_ndjson_worker, args=(i, VECTOR_HOST, TCP_PORT), daemon=True)
        t.start()
        threads.append(t)

    for i in range(SYSLOG_WORKERS):
        t = Thread(target=_syslog_worker, args=(i, VECTOR_HOST, SYSLOG_PORT), daemon=True)
        t.start()
        threads.append(t)

    # Wait for workers to connect
    time.sleep(1)

    start = time.perf_counter()
    last_print = start
    deadline = start + DURATION

    try:
        while not _stop.is_set() and time.perf_counter() < deadline:
            time.sleep(0.5)
            now = time.perf_counter()
            elapsed = now - start

            total_sent = sum(s.sent for s in _global_stats)
            total_errors = sum(s.errors for s in _global_stats)

            if now - last_print >= 1.0:
                avg_eps = int(total_sent / elapsed) if elapsed > 0 else 0

                # Compute instant EPS
                instant_eps = avg_eps  # simplified
                print(f"  [{elapsed:7.1f}s] sent={total_sent:>12,}  "
                      f"avg={avg_eps:>8,} eps  errors={total_errors}", flush=True)
                last_print = now

    except KeyboardInterrupt:
        pass

    _stop.set()
    end = time.perf_counter()
    duration = end - start

    # Wait for threads to stop
    for t in threads:
        t.join(timeout=5)

    total_sent = sum(s.sent for s in _global_stats)
    total_errors = sum(s.errors for s in _global_stats)
    avg_eps = int(total_sent / duration) if duration > 0 else 0

    print()
    print(f"  Stopping workers…")
    print()
    print(f"╔══════════════════════════════════════════════════════╗")
    print(f"║   RESULTS  (Vector End-to-End)                      ║")
    print(f"╠══════════════════════════════════════════════════════╣")
    print(f"║ Total Sent   : {total_sent:>12,}{' '*25}║")
    print(f"║ Duration     : {duration:>12.1f}s{' '*24}║")
    print(f"║ Avg EPS      : {avg_eps:>12,}{' '*25}║")
    print(f"║ Errors       : {total_errors:>12,}{' '*25}║")
    print(f"║ Workers      : {WORKERS} TCP + {SYSLOG_WORKERS} Syslog{' '*(24-len(str(WORKERS))-len(str(SYSLOG_WORKERS)))}║")
    print(f"╚══════════════════════════════════════════════════════╝")
    print()
    print("  Note: These events go through Vector's full transform")
    print("  pipeline (parse → classify → normalize → Kafka sink)")
    print("  before reaching Redpanda → Consumer → ClickHouse.")


if __name__ == "__main__":
    main()
