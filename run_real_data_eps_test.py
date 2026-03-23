#!/usr/bin/env python3
"""
CLIF Vector EPS Test — REAL DATA from agents/Data
===================================================
Replays ACTUAL log data from the CLIF dataset collection through Vector's
input ports, NOT synthetic/templated events.

Data sources:
  1. SSH Zenodo (655K real OpenSSH auth logs)      → Syslog TCP :1514
  2. Loghub Linux (25K real syslog lines)          → Syslog TCP :1514
  3. OpenSSH 2k (2K structured SSH logs)           → Syslog TCP :1514
  4. Linux 2k auth (2K real auth failure logs)      → Syslog TCP :1514
  5. CICIDS2017 (30K network flow records)         → TCP NDJSON :9514
  6. UNSW-NB15 (20K firewall/IDS records)          → TCP NDJSON :9514
  7. NSL-KDD (24K IDS records)                     → TCP NDJSON :9514
  8. EVTX attack samples (9.8K Windows events)     → TCP NDJSON :9514
  9. CSIC 2010 (61K web server requests)           → TCP NDJSON :9514

Full pipeline:
  Script → Vector (TCP:9514 / Syslog:1514)
    → mega_transform (parse + classify + normalize)
    → route_by_type
    → Redpanda (4 topics)
    → Go Consumer (batch insert)
    → ClickHouse

Usage:
    python run_real_data_eps_test.py --duration 120
    python run_real_data_eps_test.py --duration 60 --workers 4 --syslog-workers 2
"""
from __future__ import annotations

import argparse
import csv
import os
import signal
import socket
import sys
import time
from datetime import datetime, timezone
from threading import Event, Lock, Thread
from typing import List

try:
    import orjson
    def _fast_dumps(obj: dict) -> bytes:
        return orjson.dumps(obj) + b"\n"
except ImportError:
    import json
    def _fast_dumps(obj: dict) -> bytes:
        return (json.dumps(obj) + "\n").encode()

# ── CLI ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="CLIF Real-Data EPS Test")
parser.add_argument("--vector-host", default="localhost")
parser.add_argument("--tcp-port", type=int, default=9514)
parser.add_argument("--syslog-port", type=int, default=1514)
parser.add_argument("--duration", type=int, default=120)
parser.add_argument("--workers", type=int, default=4, help="TCP NDJSON workers")
parser.add_argument("--syslog-workers", type=int, default=4, help="Syslog workers")
parser.add_argument("--data-dir", default=r"c:\CLIF\agents\Data")
args = parser.parse_args()

VECTOR_HOST = args.vector_host
TCP_PORT = args.tcp_port
SYSLOG_PORT = args.syslog_port
DURATION = args.duration
DATA_DIR = args.data_dir

_stop = Event()
_counter_lock = Lock()
_total_sent = 0
_total_errors = 0

def _sigint(sig, frame):
    print("\n[!] Ctrl+C — stopping…")
    _stop.set()
signal.signal(signal.SIGINT, _sigint)

_UTC = timezone.utc

def _now_iso() -> str:
    return datetime.now(_UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# =============================================================================
#  DATA LOADERS — Read real files into memory as pre-serialized byte lines
# =============================================================================

def _load_syslog_lines() -> List[bytes]:
    """Load real syslog/SSH log files as raw RFC3164 lines for port 1514."""
    lines: List[bytes] = []
    syslog_files = [
        os.path.join(DATA_DIR, "New_Dataset", "OPEN_SSH", "SSH_from_zenodo", "SSH.log"),
        os.path.join(DATA_DIR, "New_Dataset", "Loghub", "Linux.log"),
        os.path.join(DATA_DIR, "New_Dataset", "Loghub", "loghub-linux", "Linux_2k.log"),
        os.path.join(DATA_DIR, "New_Dataset", "OPEN_SSH", "OpenSSH_from_logpaigithub", "OpenSSH_2k.log"),
        os.path.join(DATA_DIR, "datasets", "01_syslog_linux_auth", "path_c_arf", "Loghub_Linux", "Linux_2k.log"),
    ]
    for fpath in syslog_files:
        if not os.path.exists(fpath):
            print(f"  [WARN] Missing: {fpath}")
            continue
        count = 0
        with open(fpath, "r", errors="replace") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                # Wrap in RFC3164 priority if not already present
                if raw.startswith("<"):
                    lines.append(raw.encode("utf-8", errors="replace") + b"\n")
                else:
                    lines.append(b"<34>" + raw.encode("utf-8", errors="replace") + b"\n")
                count += 1
        print(f"  Loaded {count:>10,} syslog lines from {os.path.basename(fpath)}")
    return lines


def _load_csv_as_ndjson(fpath: str, source_name: str, max_rows: int = 0) -> List[bytes]:
    """Load a CSV file, convert each row to NDJSON for port 9514."""
    if not os.path.exists(fpath):
        print(f"  [WARN] Missing: {fpath}")
        return []

    rows: List[bytes] = []
    with open(fpath, "r", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return []
        for i, row in enumerate(reader):
            if max_rows and i >= max_rows:
                break
            # Build structured event with real data
            event = {
                "timestamp": _now_iso(),
                "source_dataset": source_name,
            }
            # Copy all CSV fields as-is (preserves real data)
            for k, v in row.items():
                if k and v is not None:
                    clean_k = k.strip().replace(" ", "_").replace("/", "_")
                    event[clean_k] = v.strip() if isinstance(v, str) else v
            rows.append(_fast_dumps(event))
    print(f"  Loaded {len(rows):>10,} NDJSON rows from {os.path.basename(fpath)} [{source_name}]")
    return rows


def _load_evtx_csv(fpath: str) -> List[bytes]:
    """Load real Windows EVTX attack data as NDJSON."""
    if not os.path.exists(fpath):
        print(f"  [WARN] Missing: {fpath}")
        return []

    rows: List[bytes] = []
    with open(fpath, "r", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return []
        for row in reader:
            event = {
                "timestamp": _now_iso(),
                "source_dataset": "evtx_attack_samples",
                "clif_event_type": "security",
            }
            # Map key Windows event fields
            if row.get("EventID"):
                event["EventID"] = row["EventID"]
            if row.get("ProviderName"):
                event["source"] = row["ProviderName"]
            if row.get("Computer"):
                event["hostname"] = row["Computer"]
            if row.get("Channel"):
                event["Channel"] = row["Channel"]
            if row.get("EVTX_Tactic"):
                event["mitre_tactic"] = row["EVTX_Tactic"]
                event["attack_cat"] = row["EVTX_Tactic"]
            if row.get("EVTX_FileName"):
                event["description"] = row["EVTX_FileName"]
            if row.get("IpAddress") and row["IpAddress"] != "-":
                event["ip_address"] = row["IpAddress"]
            if row.get("TargetUserName"):
                event["user_id"] = row["TargetUserName"]
            if row.get("ProcessName"):
                event["binary_path"] = row["ProcessName"]
            if row.get("Level"):
                event["level"] = row["Level"]
            # Build message from key fields for Vector classification
            parts = []
            if row.get("EVTX_Tactic"):
                parts.append(row["EVTX_Tactic"])
            if row.get("ProviderName"):
                parts.append(row["ProviderName"])
            if row.get("EventID"):
                parts.append(f"EventID={row['EventID']}")
            if row.get("TargetUserName"):
                parts.append(f"user={row['TargetUserName']}")
            event["message"] = " | ".join(parts) if parts else "Windows Event"

            rows.append(_fast_dumps(event))
    print(f"  Loaded {len(rows):>10,} NDJSON rows from evtx_data.csv [Windows EVTX]")
    return rows


def _load_web_csv(fpath: str) -> List[bytes]:
    """Load CSIC 2010 web attack data as NDJSON."""
    if not os.path.exists(fpath):
        print(f"  [WARN] Missing: {fpath}")
        return []

    rows: List[bytes] = []
    with open(fpath, "r", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return []
        for row in reader:
            method = row.get("Method", "GET")
            url = row.get("URL", "/")
            classification = row.get("classification", "0")
            host = row.get("host", "localhost")
            ua = row.get("User-Agent", "")
            content = row.get("content", "")

            event = {
                "timestamp": _now_iso(),
                "source_dataset": "csic_2010_web",
                "hostname": host,
                "method": method,
                "url": url,
                "user_agent": ua,
                "message": f'{method} {url} - {host} - classification={classification}',
            }
            if content:
                event["content"] = content[:512]  # Limit content size
            if classification == "1":
                event["attack_cat"] = "web-attack"
                event["label"] = "1"
            rows.append(_fast_dumps(event))
    print(f"  Loaded {len(rows):>10,} NDJSON rows from csic_database.csv [Web logs]")
    return rows


# =============================================================================
#  SENDER THREADS
# =============================================================================

def _syslog_sender(worker_id: int, lines: List[bytes]):
    """Replay real syslog lines through Vector's syslog TCP port."""
    global _total_sent, _total_errors
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    try:
        sock.connect((VECTOR_HOST, SYSLOG_PORT))
    except Exception as e:
        print(f"  [Syslog-{worker_id}] Connect failed: {e}")
        return

    n = len(lines)
    if n == 0:
        return
    idx = worker_id  # Start at different offsets for different workers
    local_sent = 0
    batch = bytearray()
    BATCH_LIMIT = 256 * 1024  # 256KB batch

    while not _stop.is_set():
        line = lines[idx % n]
        idx += 1
        batch.extend(line)

        if len(batch) >= BATCH_LIMIT:
            try:
                sock.sendall(bytes(batch))
                count = batch.count(b"\n")
                local_sent += count
                with _counter_lock:
                    _total_sent += count
            except Exception:
                with _counter_lock:
                    _total_errors += 1
                # Reconnect
                try:
                    sock.close()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
                    sock.connect((VECTOR_HOST, SYSLOG_PORT))
                except Exception:
                    break
            batch = bytearray()

    # Flush remainder
    if batch:
        try:
            sock.sendall(bytes(batch))
            count = batch.count(b"\n")
            with _counter_lock:
                _total_sent += count
        except Exception:
            pass
    sock.close()


def _tcp_json_sender(worker_id: int, lines: List[bytes]):
    """Replay real CSV-converted NDJSON through Vector's TCP port."""
    global _total_sent, _total_errors
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    try:
        sock.connect((VECTOR_HOST, TCP_PORT))
    except Exception as e:
        print(f"  [TCP-{worker_id}] Connect failed: {e}")
        return

    n = len(lines)
    if n == 0:
        return
    idx = worker_id * (n // max(args.workers, 1))
    local_sent = 0
    batch = bytearray()
    BATCH_LIMIT = 256 * 1024

    while not _stop.is_set():
        line = lines[idx % n]
        idx += 1
        batch.extend(line)

        if len(batch) >= BATCH_LIMIT:
            try:
                sock.sendall(bytes(batch))
                count = batch.count(b"\n")
                local_sent += count
                with _counter_lock:
                    _total_sent += count
            except Exception:
                with _counter_lock:
                    _total_errors += 1
                try:
                    sock.close()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
                    sock.connect((VECTOR_HOST, TCP_PORT))
                except Exception:
                    break
            batch = bytearray()

    if batch:
        try:
            sock.sendall(bytes(batch))
            count = batch.count(b"\n")
            with _counter_lock:
                _total_sent += count
        except Exception:
            pass
    sock.close()


# =============================================================================
#  MAIN
# =============================================================================

def main():
    global _total_sent, _total_errors

    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║   CLIF Vector EPS Test — REAL DATA from agents/Data    ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║ Vector Host : {VECTOR_HOST:<42s} ║")
    print(f"║ TCP NDJSON  : port {TCP_PORT} ({args.workers} workers){' ' * 24}║")
    print(f"║ Syslog TCP  : port {SYSLOG_PORT} ({args.syslog_workers} workers){' ' * 23}║")
    print(f"║ Duration    : {DURATION}s{' ' * 40}║")
    print("║ Pipeline    : RealData→Vector→Redpanda→Consumer→CH     ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # ── Phase 1: Load all real data ────────────────────────────────────────
    print("\n[1/3] Loading real log data from agents/Data …\n")

    # Syslog data (raw log lines)
    syslog_lines = _load_syslog_lines()

    # CSV → NDJSON data
    ndjson_lines: List[bytes] = []

    ndjson_lines.extend(_load_csv_as_ndjson(
        os.path.join(DATA_DIR, "datasets", "01_syslog_linux_auth", "path_a_lightgbm", "CICIDS2017", "cicids2017_stratified.csv"),
        "cicids2017"))

    ndjson_lines.extend(_load_csv_as_ndjson(
        os.path.join(DATA_DIR, "datasets", "03_firewall_cef", "path_a_lightgbm", "UNSW-NB15", "unsw_stratified.csv"),
        "unsw_nb15"))

    ndjson_lines.extend(_load_csv_as_ndjson(
        os.path.join(DATA_DIR, "datasets", "10_ids_ips_zeek", "path_a_lightgbm", "NSL-KDD", "nsl_kdd_stratified.csv"),
        "nsl_kdd"))

    ndjson_lines.extend(_load_evtx_csv(
        os.path.join(DATA_DIR, "datasets", "02_windows_event_log", "path_a_lightgbm", "EVTX-ATTACK-SAMPLES", "evtx_data.csv")))

    ndjson_lines.extend(_load_web_csv(
        os.path.join(DATA_DIR, "datasets", "08_nginx_web_server", "path_a_lightgbm", "CSIC_2010", "csic_database.csv")))

    ndjson_lines.extend(_load_csv_as_ndjson(
        os.path.join(DATA_DIR, "datasets", "09_netflow_ipfix", "path_a_lightgbm", "NF-UNSW-NB15-v3", "nf_unsw_stratified.csv"),
        "nf_unsw_nb15"))

    total_syslog = len(syslog_lines)
    total_ndjson = len(ndjson_lines)
    syslog_mb = sum(len(l) for l in syslog_lines) / 1024 / 1024
    ndjson_mb = sum(len(l) for l in ndjson_lines) / 1024 / 1024

    print(f"\n  Total syslog pool : {total_syslog:>10,} lines  ({syslog_mb:,.1f} MB)")
    print(f"  Total NDJSON pool : {total_ndjson:>10,} lines  ({ndjson_mb:,.1f} MB)")
    print(f"  Combined pool     : {total_syslog + total_ndjson:>10,} real events")

    if total_syslog == 0 and total_ndjson == 0:
        print("\n[ERROR] No data loaded. Check --data-dir path.")
        sys.exit(1)

    # ── Phase 2: Launch sender threads ─────────────────────────────────────
    print(f"\n[2/3] Launching {args.syslog_workers} syslog + {args.workers} TCP workers for {DURATION}s …\n")

    threads: List[Thread] = []
    for i in range(args.syslog_workers):
        t = Thread(target=_syslog_sender, args=(i, syslog_lines), daemon=True)
        threads.append(t)
    for i in range(args.workers):
        t = Thread(target=_tcp_json_sender, args=(i, ndjson_lines), daemon=True)
        threads.append(t)

    t0 = time.monotonic()
    for t in threads:
        t.start()

    # ── Phase 3: Monitor progress ──────────────────────────────────────────
    while not _stop.is_set():
        time.sleep(1.0)
        elapsed = time.monotonic() - t0
        if elapsed >= DURATION:
            break
        with _counter_lock:
            snap = _total_sent
            errs = _total_errors
        eps = int(snap / elapsed) if elapsed > 0 else 0
        print(f"  [{elapsed:7.1f}s] sent={snap:>12,}  avg={eps:>8,} eps  errors={errs}")

    _stop.set()
    print("\n  Stopping workers…")
    for t in threads:
        t.join(timeout=5)

    elapsed = time.monotonic() - t0
    final_eps = int(_total_sent / elapsed) if elapsed > 0 else 0

    print(f"\n╔══════════════════════════════════════════════════════════╗")
    print(f"║   RESULTS  (Real Data → Vector End-to-End)              ║")
    print(f"╠══════════════════════════════════════════════════════════╣")
    print(f"║ Total Sent   : {_total_sent:>12,}{' ' * 28}║")
    print(f"║ Duration     : {elapsed:>12.1f}s{' ' * 27}║")
    print(f"║ Avg EPS      : {final_eps:>12,}{' ' * 28}║")
    print(f"║ Errors       : {_total_errors:>12}{' ' * 28}║")
    print(f"║ Workers      : {args.syslog_workers} Syslog + {args.workers} TCP{' ' * 26}║")
    print(f"║ Data Source  : agents/Data (REAL logs){' ' * 16}║")
    print(f"╚══════════════════════════════════════════════════════════╝")
    print(f"\n  Syslog pool : {total_syslog:,} lines ({syslog_mb:.1f} MB) — SSH, Linux auth, system logs")
    print(f"  NDJSON pool : {total_ndjson:,} lines ({ndjson_mb:.1f} MB) — CICIDS, UNSW, NSL-KDD, EVTX, Web, NetFlow")
    print(f"\n  Events flow through Vector's full transform pipeline")
    print(f"  (parse → classify → normalize → Kafka sink)")
    print(f"  before reaching Redpanda → Consumer → ClickHouse.\n")


if __name__ == "__main__":
    main()
